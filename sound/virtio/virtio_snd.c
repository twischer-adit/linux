// SPDX-License-Identifier: GPL-2.0+
/*
 * Sound card driver for virtio
 * Copyright (C) 2019  OpenSynergy GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/atomic.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_snd.h>

#include <sound/core.h>
#include <sound/initval.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>

static int pcm_buffer_ms = 250;
module_param(pcm_buffer_ms, int, 0644);
MODULE_PARM_DESC(pcm_buffer_ms, "PCM substream buffer size in milliseconds");

/*
 * The main goal of this parameter is eliminating issue with double scheduling.
 * The value should be big enough to avoid underflow conditions due to worst
 * possible task schedule latency on both sides. Depending on actual system
 * setup, minimal suitable value can vary and belongs to [20 .. 80] range
 * (according to different tests). Thus, 50 ms look good enough as an averaged
 * default value.
 */
static int pcm_target_ms = 50;
module_param(pcm_target_ms, int, 0644);
MODULE_PARM_DESC(pcm_target_ms, "PCM playback target size in milliseconds");

static int pcm_xfer_ms = 10;
module_param(pcm_xfer_ms, int, 0644);
MODULE_PARM_DESC(pcm_xfer_ms, "PCM transfer step size in milliseconds");

/* a control message proxy structure */
struct viosnd_msg {
	bool notify;
	wait_queue_head_t wait_completed;
	bool completed;
	struct virtio_snd_hdr *request;
	size_t request_size;
	struct virtio_snd_hdr *response;
	size_t response_size;
};

/* a virtqueue proxy structure */
struct viosnd_queue {
	struct virtio_snd_queue_info info;
	struct virtqueue *vqueue;
	void *data;
};

/* a driver private context structure */
struct viosnd_ctx {
	struct virtio_device *vdev;
	struct snd_card *card;
	/* queues management */
	struct viosnd_queue *queues;
	u32 nqueues;
	/* control queue */
	spinlock_t lock;
	unsigned int msg_count;
	wait_queue_head_t wait_available;
};

struct viosnd_pcm;
struct viosnd_pcm_stream;

/* a PCM message proxy structure */
struct viosnd_pcm_msg {
	/* IO request header */
	u8 stream_type;
	/* IO request status */
	u32 status;
	/* original size of IO request (in frames) */
	snd_pcm_uframes_t size;
	/* true = do not update a hardware pointer */
	bool unaccounted;
};

enum {
	PCM_XFER_DISABLED = 0,
	PCM_XFER_ENABLED,
	PCM_XFER_PENDING
};

struct viosnd_pcm_stream {
	struct viosnd_pcm *pcm;

	struct snd_pcm_hardware hw;
	struct snd_pcm_substream *substream;
	u8 nchmaps;

	struct hrtimer hrt;

	atomic64_t hw_ptr;
	snd_pcm_uframes_t period_ptr;
	void *silence;
	snd_pcm_uframes_t xfer_carry_frames;
	u64 xfer_start_ns;
	u64 xfer_carry_ns;
	wait_queue_head_t wait_xfer_state;
	/* data transport state: PCM_XFER_* */
	atomic_t xfer_state;
};

struct viosnd_pcm {
	struct viosnd_ctx *ctx;
	struct snd_pcm *pcm;
	struct viosnd_pcm_stream *streams[2];
	/* protects PCM data queue */
	spinlock_t lock;
};

static inline bool viosnd_activate_queue(struct viosnd_ctx *ctx, u16 function,
					 u8 device_id, u8 subdevice_id,
					 void *data)
{
	u32 i;

	for (i = 0; i < ctx->nqueues; ++i) {
		struct viosnd_queue *queue = ctx->queues + i;

		if (queue->info.function != function)
			continue;

		if (queue->info.device_id != device_id)
			continue;

		if (queue->info.subdevice_id != subdevice_id)
			continue;

		queue->data = data;

		virtqueue_enable_cb(queue->vqueue);

		return true;
	}

	return false;
}

static inline struct virtqueue *viosnd_find_vqueue(struct viosnd_ctx *ctx,
						   void *data)
{
	u32 i;

	for (i = 0; i < ctx->nqueues; ++i)
		if (ctx->queues[i].data == data)
			return ctx->queues[i].vqueue;

	return NULL;
}

static inline void *viosnd_find_data(struct viosnd_ctx *ctx,
				     struct virtqueue *vqueue)
{
	u32 i;

	for (i = 0; i < ctx->nqueues; ++i)
		if (ctx->queues[i].vqueue == vqueue)
			return ctx->queues[i].data;

	return NULL;
}

static inline bool viosnd_ctl_msg_wait_available(struct viosnd_ctx *ctx,
						 unsigned int msecs)
{
	int code;
	unsigned long js = msecs_to_jiffies(msecs);

	if (!js)
		return false;

	code = wait_event_interruptible_lock_irq_timeout(ctx->wait_available,
							 ctx->msg_count,
							 ctx->lock,
							 js);

	return (code > 0) ? true : false;
}

static struct viosnd_msg *viosnd_ctl_msg_get(struct viosnd_ctx *ctx,
					     size_t request_size,
					     size_t response_size,
					     gfp_t gfp,
					     unsigned int msecs)
{
	struct device *dev = &ctx->vdev->dev;
	struct viosnd_msg *msg;
	unsigned long flags;

	msg = devm_kzalloc(dev, sizeof(*msg), gfp);
	if (!msg)
		return ERR_PTR(-ENOMEM);

	msg->request = devm_kzalloc(dev, request_size, gfp);
	if (!msg->request) {
		devm_kfree(dev, msg);
		return ERR_PTR(-ENOMEM);
	}

	msg->response = devm_kzalloc(dev, response_size, gfp);
	if (!msg->response) {
		devm_kfree(dev, msg->request);
		devm_kfree(dev, msg);
		return ERR_PTR(-ENOMEM);
	}

	msg->request_size = request_size;
	msg->response_size = response_size;
	init_waitqueue_head(&msg->wait_completed);

	spin_lock_irqsave(&ctx->lock, flags);
	if (!ctx->msg_count)
		if (!viosnd_ctl_msg_wait_available(ctx, msecs)) {
			devm_kfree(dev, msg->response);
			devm_kfree(dev, msg->request);
			devm_kfree(dev, msg);
			msg = ERR_PTR(-ENOENT);
			goto on_failure;
		}

	ctx->msg_count--;

on_failure:
	spin_unlock_irqrestore(&ctx->lock, flags);

	return msg;
}

static void viosnd_ctl_msg_put_nolock(struct viosnd_ctx *ctx,
				      struct viosnd_msg *msg)
{
	struct device *dev = &ctx->vdev->dev;

	devm_kfree(dev, msg->response);
	devm_kfree(dev, msg->request);
	devm_kfree(dev, msg);

	ctx->msg_count++;
	wake_up(&ctx->wait_available);
}

static void viosnd_ctl_msg_put(struct viosnd_ctx *ctx, struct viosnd_msg *msg)
{
	unsigned long flags;

	spin_lock_irqsave(&ctx->lock, flags);
	viosnd_ctl_msg_put_nolock(ctx, msg);
	spin_unlock_irqrestore(&ctx->lock, flags);
}

static void viosnd_ctl_notify_cb(struct virtqueue *vqueue)
{
	struct viosnd_ctx *ctx = vqueue->vdev->priv;
	unsigned long flags;

	spin_lock_irqsave(&ctx->lock, flags);

	do {
		struct viosnd_msg *msg;
		unsigned int length;

		virtqueue_disable_cb(vqueue);

		while ((msg = virtqueue_get_buf(vqueue, &length))) {
			if (msg->notify) {
				msg->completed = true;
				wake_up(&msg->wait_completed);

				continue;
			}

			viosnd_ctl_msg_put_nolock(ctx, msg);
		}

		if (unlikely(virtqueue_is_broken(vqueue)))
			break;
	} while (!virtqueue_enable_cb(vqueue));

	spin_unlock_irqrestore(&ctx->lock, flags);
}

static inline int viosnd_ctl_msg_status(u32 status)
{
	switch (status) {
	case VIRTIO_SND_S_OK:
		return 0;
	case VIRTIO_SND_S_ENOTSUPPORTED:
		return -EOPNOTSUPP;
	case VIRTIO_SND_S_EINVALID:
		return -EINVAL;
	case VIRTIO_SND_S_EIO:
		return -EIO;
	default:
		return -EPERM;
	}
}

static inline int viosnd_ctl_msg_wait_completed(struct viosnd_msg *msg,
						unsigned int msecs)
{
	int code;

	code = wait_event_interruptible_timeout(msg->wait_completed,
						msg->completed,
						msecs_to_jiffies(msecs));

	if (code > 0)
		code = viosnd_ctl_msg_status(le32_to_cpu(msg->response->code));
	else
		code = -EIO;

	return code;
}

static inline int viosnd_ctl_msg_send(struct viosnd_ctx *ctx,
				      struct viosnd_msg *msg,
				      unsigned int msecs)
{
	int code;
	struct virtqueue *vqueue;
	struct scatterlist sg_request;
	struct scatterlist sg_response;
	struct scatterlist *sgs[2] = { &sg_request, &sg_response };
	bool notify = false;
	unsigned long flags;

	vqueue = viosnd_find_vqueue(ctx, ctx);
	if (!vqueue)
		return -ENODEV;

	msg->completed = false;
	msg->notify = !!msecs;

	sg_init_one(&sg_request, msg->request, msg->request_size);
	sg_init_one(&sg_response, msg->response, msg->response_size);

	spin_lock_irqsave(&ctx->lock, flags);
	code = virtqueue_add_sgs(vqueue, sgs, 1, 1, msg, GFP_ATOMIC);
	if (!code)
		notify = virtqueue_kick_prepare(vqueue);
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (!code) {
		if (notify)
			virtqueue_notify(vqueue);

		if (msg->notify)
			code = viosnd_ctl_msg_wait_completed(msg, msecs);
	}

	return code;
}

static inline struct viosnd_pcm_stream *
viosnd_pcm_substream_ctx(struct snd_pcm_substream *substream)
{
	struct viosnd_pcm *pcm = substream->private_data;

	switch (substream->stream) {
	case SNDRV_PCM_STREAM_PLAYBACK:
		return pcm->streams[VIRTIO_SND_PCM_T_PLAYBACK];
	case SNDRV_PCM_STREAM_CAPTURE:
		return pcm->streams[VIRTIO_SND_PCM_T_CAPTURE];
	}

	return NULL;
}

static inline void viosnd_pcm_set_hdr(struct virtio_snd_pcm_hdr *hdr,
				      struct viosnd_pcm_stream *stream,
				      u32 request)
{
	struct virtio_device *vdev = stream->pcm->ctx->vdev;

	hdr->hdr.code = cpu_to_virtio32(vdev, request);
	hdr->pcm_id = stream->pcm->pcm->device;
	hdr->stream_type =
		(stream->substream->stream == SNDRV_PCM_STREAM_PLAYBACK) ?
			VIRTIO_SND_PCM_T_PLAYBACK :
			VIRTIO_SND_PCM_T_CAPTURE;
}

static int viosnd_pcm_send_generic(struct viosnd_pcm_stream *stream,
				   u32 command, gfp_t gfp, unsigned int msecs)
{
	int code;
	struct viosnd_ctx *ctx = stream->pcm->ctx;
	struct viosnd_msg *msg;

	msg = viosnd_ctl_msg_get(ctx, sizeof(struct virtio_snd_pcm_hdr),
				 sizeof(struct virtio_snd_hdr), gfp, msecs);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	viosnd_pcm_set_hdr((struct virtio_snd_pcm_hdr *)msg->request, stream,
			   command);

	code = viosnd_ctl_msg_send(ctx, msg, msecs);

	if (msecs)
		viosnd_ctl_msg_put(ctx, msg);

	return code;
}

static void viosnd_pcm_silence(struct viosnd_pcm_stream *stream,
			       snd_pcm_uframes_t frames, gfp_t gfp)
{
	int code;
	struct snd_pcm_runtime *runtime = stream->substream->runtime;
	struct viosnd_pcm *pcm = stream->pcm;
	struct virtio_device *vdev = pcm->ctx->vdev;
	struct virtqueue *vqueue;
	struct device *dev = &vdev->dev;
	struct viosnd_pcm_msg *msg;
	struct scatterlist sgs[3] = { 0 };
	struct scatterlist *psgs[3] = { &sgs[0], &sgs[1], &sgs[2] };
	unsigned long flags;
	bool notify = false;

	vqueue = viosnd_find_vqueue(pcm->ctx, pcm);
	if (!vqueue)
		return;

	msg = devm_kzalloc(dev, sizeof(*msg), gfp);
	if (!msg)
		return;

	msg->stream_type = VIRTIO_SND_PCM_T_PLAYBACK;
	msg->size = frames;
	msg->unaccounted = true;

	sg_init_one(psgs[0], &msg->stream_type, sizeof(msg->stream_type));
	sg_init_one(psgs[1], stream->silence,
		    frames_to_bytes(runtime, frames));
	sg_init_one(psgs[2], &msg->status, sizeof(msg->status));

	spin_lock_irqsave(&pcm->lock, flags);
	code = virtqueue_add_sgs(vqueue, psgs, 2, 1, msg, GFP_ATOMIC);
	if (!code)
		notify = virtqueue_kick_prepare(vqueue);
	else
		devm_kfree(dev, msg);
	spin_unlock_irqrestore(&pcm->lock, flags);

	if (notify)
		virtqueue_notify(vqueue);
}

static void viosnd_pcm_xfer(struct viosnd_pcm_stream *stream,
			    snd_pcm_uframes_t position,
			    snd_pcm_uframes_t frames, gfp_t gfp)
{
	int code;
	bool is_playback =
		(stream->substream->stream == SNDRV_PCM_STREAM_PLAYBACK);
	struct snd_pcm_runtime *runtime = stream->substream->runtime;
	struct viosnd_pcm *pcm = stream->pcm;
	struct virtio_device *vdev = pcm->ctx->vdev;
	struct virtqueue *vqueue;
	struct device *dev = &vdev->dev;
	struct viosnd_pcm_msg *msg;
	struct scatterlist sgs[4] = { 0 };
	struct scatterlist *psgs[4] = { 0 };
	unsigned long nsgs = 0;
	unsigned long flags;
	bool notify = false;

	vqueue = viosnd_find_vqueue(pcm->ctx, pcm);
	if (!vqueue)
		return;

	msg = devm_kzalloc(dev, sizeof(*msg), gfp);
	if (!msg)
		return;

	if (is_playback)
		msg->stream_type = VIRTIO_SND_PCM_T_PLAYBACK;
	else
		msg->stream_type = VIRTIO_SND_PCM_T_CAPTURE;

	msg->size = frames;

	psgs[nsgs] = &sgs[nsgs];
	sg_init_one(psgs[nsgs++], &msg->stream_type, sizeof(msg->stream_type));

	while (frames) {
		snd_pcm_uframes_t count = frames;
		void *data;

		if (position + count > runtime->buffer_size)
			count = runtime->buffer_size - position;

		data = runtime->dma_area + frames_to_bytes(runtime, position);

		psgs[nsgs] = &sgs[nsgs];
		sg_init_one(psgs[nsgs++], data,
			    frames_to_bytes(runtime, count));

		position = (position + count) % runtime->buffer_size;
		frames -= count;
	}

	psgs[nsgs] = &sgs[nsgs];
	sg_init_one(psgs[nsgs], &msg->status, sizeof(msg->status));

	spin_lock_irqsave(&pcm->lock, flags);
	if (is_playback)
		code = virtqueue_add_sgs(vqueue, psgs, nsgs, 1, msg,
					 GFP_ATOMIC);
	else
		code = virtqueue_add_sgs(vqueue, psgs, 1, nsgs, msg,
					 GFP_ATOMIC);

	if (!code)
		notify = virtqueue_kick_prepare(vqueue);
	else
		devm_kfree(dev, msg);
	spin_unlock_irqrestore(&pcm->lock, flags);

	if (notify)
		virtqueue_notify(vqueue);
}

static snd_pcm_uframes_t viosnd_pcm_avail_size(struct viosnd_pcm_stream *stream)
{
	struct snd_pcm_substream *substream = stream->substream;
	struct snd_pcm_runtime *runtime = substream->runtime;
	snd_pcm_uframes_t hw_ptr;
	snd_pcm_uframes_t appl_ptr;
	snd_pcm_uframes_t available;

	hw_ptr = (snd_pcm_uframes_t)atomic64_read(&stream->hw_ptr);
	appl_ptr = READ_ONCE(runtime->control->appl_ptr);

	/* calculate available space for an application */
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		available = hw_ptr + runtime->buffer_size - appl_ptr;
		if (available < 0)
			available += runtime->boundary;
		else if ((snd_pcm_uframes_t)available >= runtime->boundary)
			available -= runtime->boundary;
	} else {
		available = hw_ptr - appl_ptr;
		if (available < 0)
			available += runtime->boundary;
	}

	/* calculate available space for a hardware */
	return runtime->buffer_size - available;
}

static snd_pcm_uframes_t viosnd_pcm_xfer_size(struct viosnd_pcm_stream *stream)
{
	struct snd_pcm_substream *substream = stream->substream;
	struct snd_pcm_runtime *runtime = substream->runtime;
	snd_pcm_uframes_t frames;
	snd_pcm_sframes_t available;
	snd_pcm_sframes_t xfer_size;
	u64 current_ns;
	u64 ns;

	/* calculate an amount of elapsed nanoseconds */
	current_ns = ktime_get_raw_ns();
	ns = current_ns - stream->xfer_start_ns;
	stream->xfer_start_ns = current_ns;

	/* calculate an amount of elapsed frames */
	frames = (runtime->rate * ns + stream->xfer_carry_ns) / NSEC_PER_SEC;
	frames += stream->xfer_carry_frames;
	stream->xfer_carry_ns =
		(runtime->rate * ns + stream->xfer_carry_ns) % NSEC_PER_SEC;

	available = viosnd_pcm_avail_size(stream);

	xfer_size = min_t(snd_pcm_uframes_t, frames, available);
	stream->xfer_carry_frames = frames - xfer_size;

	return xfer_size;
}

static enum hrtimer_restart viosnd_pcm_timer_cb(struct hrtimer *hrt)
{
	struct viosnd_pcm_stream *stream =
		container_of(hrt, struct viosnd_pcm_stream, hrt);
	struct snd_pcm_substream *substream = stream->substream;

	snd_pcm_uframes_t frames;
	u64 ns = pcm_xfer_ms * NSEC_PER_MSEC;

	/* if transport is enabled, set state to PCM_XFER_PENDING */
	if (!atomic_inc_not_zero(&stream->xfer_state))
		return HRTIMER_NORESTART;

	frames = viosnd_pcm_xfer_size(stream);

	if (frames) {
		struct snd_pcm_runtime *runtime = substream->runtime;
		snd_pcm_uframes_t hw_ptr;

		hw_ptr = (snd_pcm_uframes_t)atomic64_read(&stream->hw_ptr);

		viosnd_pcm_xfer(stream, hw_ptr % runtime->buffer_size, frames,
				GFP_ATOMIC);

		ns = min_t(u64, ns, frames * (NSEC_PER_SEC / runtime->rate));
	} else {
		/* there's no pending request */
		atomic_dec(&stream->xfer_state);
	}

	hrtimer_forward_now(hrt, ns_to_ktime(ns));

	return HRTIMER_RESTART;
}

static inline void viosnd_pcm_xfer_complete(struct viosnd_pcm *pcm,
					    struct viosnd_pcm_msg *msg,
					    u32 actual_bytes)
{
	struct viosnd_pcm_stream *stream;
	struct snd_pcm_substream *substream;
	struct snd_pcm_runtime *runtime;
	snd_pcm_uframes_t hw_ptr;
	snd_pcm_uframes_t frames;
	bool period_elapsed = false;

	switch (msg->stream_type) {
	case VIRTIO_SND_PCM_T_PLAYBACK:
	case VIRTIO_SND_PCM_T_CAPTURE:
		stream = pcm->streams[msg->stream_type];
		break;
	default:
		return;
	}

	/* if transport was disabled in the middle */
	if (atomic_read(&stream->xfer_state) != PCM_XFER_PENDING)
		goto on_finish;

	substream = stream->substream;
	runtime = substream->runtime;
	frames = bytes_to_frames(runtime, actual_bytes);

	stream->xfer_carry_frames += msg->size - frames;

	if (msg->unaccounted)
		goto on_finish;

	hw_ptr = (snd_pcm_uframes_t)atomic64_read(&stream->hw_ptr);
	hw_ptr += frames;
	if (hw_ptr >= runtime->boundary)
		hw_ptr -= runtime->boundary;
	atomic64_set(&stream->hw_ptr, hw_ptr);

	stream->period_ptr += frames;
	if (stream->period_ptr >= runtime->period_size) {
		stream->period_ptr -= runtime->period_size;
		period_elapsed = true;
	}

	/*
	 * When a substream is draining, ALSA waits until hardware buffer is
	 * empty. This check is performed in the snd_pcm_update_state function
	 * called from the snd_pcm_period_elapsed function. If a buffer became
	 * empty on period boundary, everything is fine. Otherwise, if there's
	 * small amount of remaining frames, a device will continue to read or
	 * write behind last valid frame till the next elapsed period
	 * notification. The following workaround allows to avoid such
	 * situation.
	 */
	if (runtime->status->state == SNDRV_PCM_STATE_DRAINING)
		if (!viosnd_pcm_avail_size(stream))
			period_elapsed = true;

on_finish:
	if (atomic_dec_return(&stream->xfer_state) == PCM_XFER_DISABLED) {
		wake_up(&stream->wait_xfer_state);

		return;
	}

	if (period_elapsed)
		snd_pcm_period_elapsed(substream);
}

static void viosnd_pcm_notify_cb(struct virtqueue *vqueue)
{
	struct viosnd_ctx *ctx = vqueue->vdev->priv;
	struct viosnd_pcm *pcm;

	pcm = viosnd_find_data(ctx, vqueue);
	if (!pcm)
		return;

	do {
		struct device *dev = &pcm->ctx->vdev->dev;

		virtqueue_disable_cb(vqueue);

		for (;;) {
			struct viosnd_pcm_msg *msg;
			unsigned long flags;
			u32 length;

			spin_lock_irqsave(&pcm->lock, flags);
			msg = virtqueue_get_buf(vqueue, &length);
			spin_unlock_irqrestore(&pcm->lock, flags);

			if (!msg)
				break;

			viosnd_pcm_xfer_complete(pcm, msg, length);

			devm_kfree(dev, msg);
		}

		if (unlikely(virtqueue_is_broken(vqueue)))
			break;
	} while (!virtqueue_enable_cb(vqueue));
}

static int viosnd_pcm_open(struct snd_pcm_substream *substream)
{
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);

	if (!stream)
		return -EBADFD;

	substream->runtime->hw = stream->hw;

	return 0;
}

static int viosnd_pcm_close(struct snd_pcm_substream *substream)
{
	return 0;
}

static int viosnd_pcm_hw_params(struct snd_pcm_substream *substream,
				struct snd_pcm_hw_params *hw_params)
{
	static const struct {
		unsigned int alsa_fmt;
		unsigned int vio_fmt;
	} fmtmap[] = {
		{ SNDRV_PCM_FORMAT_S8, VIRTIO_SND_PCM_FMT_S8 },
		{ SNDRV_PCM_FORMAT_U8, VIRTIO_SND_PCM_FMT_U8 },
		{ SNDRV_PCM_FORMAT_S16, VIRTIO_SND_PCM_FMT_S16 },
		{ SNDRV_PCM_FORMAT_U16, VIRTIO_SND_PCM_FMT_U16 },
		{ SNDRV_PCM_FORMAT_S32, VIRTIO_SND_PCM_FMT_S32 },
		{ SNDRV_PCM_FORMAT_U32, VIRTIO_SND_PCM_FMT_U32 },
		{ SNDRV_PCM_FORMAT_FLOAT, VIRTIO_SND_PCM_FMT_FLOAT },
		{ SNDRV_PCM_FORMAT_FLOAT64, VIRTIO_SND_PCM_FMT_FLOAT64 }
	};

	static const struct {
		unsigned int rate;
		unsigned int vio_rate;
	} ratemap[] = {
		{ 8000, VIRTIO_SND_PCM_RATE_8000 },
		{ 11025, VIRTIO_SND_PCM_RATE_11025 },
		{ 16000, VIRTIO_SND_PCM_RATE_16000 },
		{ 22050, VIRTIO_SND_PCM_RATE_22050 },
		{ 32000, VIRTIO_SND_PCM_RATE_32000 },
		{ 44100, VIRTIO_SND_PCM_RATE_44100 },
		{ 48000, VIRTIO_SND_PCM_RATE_48000 },
		{ 64000, VIRTIO_SND_PCM_RATE_64000 },
		{ 88200, VIRTIO_SND_PCM_RATE_88200 },
		{ 96000, VIRTIO_SND_PCM_RATE_96000 },
		{ 176400, VIRTIO_SND_PCM_RATE_176400 },
		{ 192000, VIRTIO_SND_PCM_RATE_192000 }
	};

	int code;
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);
	struct viosnd_ctx *ctx;
	struct virtio_device *vdev;
	struct device *dev;
	snd_pcm_format_t format;
	unsigned int channels;
	unsigned int rate;
	unsigned int buffer_size;
	struct viosnd_msg *msg;
	struct virtio_snd_pcm_set_format *request;
	int i;

	if (!stream)
		return -EBADFD;

	ctx = stream->pcm->ctx;
	vdev = ctx->vdev;
	dev = &vdev->dev;

	format = params_format(hw_params);
	channels = snd_pcm_hw_param_value(hw_params,
					  SNDRV_PCM_HW_PARAM_CHANNELS, NULL);
	rate = snd_pcm_hw_param_value(hw_params,
				      SNDRV_PCM_HW_PARAM_RATE, NULL);
	buffer_size = snd_pcm_hw_param_value(hw_params,
					     SNDRV_PCM_HW_PARAM_BUFFER_BYTES,
					     NULL);

	msg = viosnd_ctl_msg_get(ctx, sizeof(*request),
				 sizeof(struct virtio_snd_hdr), GFP_KERNEL,
				 1000);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	request = (struct virtio_snd_pcm_set_format *)msg->request;

	viosnd_pcm_set_hdr(&request->hdr, stream, VIRTIO_SND_R_PCM_SET_FORMAT);
	request->channels = cpu_to_virtio16(vdev, channels);
	request->format = (u16)-1;
	request->rate = (u16)-1;

	for (i = 0; i < ARRAY_SIZE(fmtmap); ++i) {
		if (fmtmap[i].alsa_fmt == format) {
			request->format =
				cpu_to_virtio16(vdev, fmtmap[i].vio_fmt);

			break;
		}
	}

	for (i = 0; i < ARRAY_SIZE(ratemap); ++i) {
		if (ratemap[i].rate == rate) {
			request->rate =
				cpu_to_virtio16(vdev, ratemap[i].vio_rate);

			break;
		}
	}

	if ((request->format == (u16)-1) || (request->rate == (u16)-1)) {
		code = -EINVAL;
		goto on_failure;
	}

	code = viosnd_ctl_msg_send(ctx, msg, 1000);
	if (code != 0)
		goto on_failure;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		unsigned int sample_bits;
		unsigned int frame_bits;
		unsigned int silence_bytes;
		unsigned int samples;

		sample_bits =
			snd_pcm_hw_param_value(hw_params,
					       SNDRV_PCM_HW_PARAM_SAMPLE_BITS,
					       NULL);

		frame_bits =
			snd_pcm_hw_param_value(hw_params,
					       SNDRV_PCM_HW_PARAM_FRAME_BITS,
					       NULL);

		silence_bytes =
			(frame_bits / 8) * pcm_target_ms *
			(rate / MSEC_PER_SEC);

		stream->silence = devm_kmalloc(dev, silence_bytes, GFP_KERNEL);
		if (!stream->silence) {
			code = -ENOMEM;
			goto on_failure;
		}

		samples = silence_bytes * 8 / sample_bits;

		code = snd_pcm_format_set_silence(format, stream->silence,
						  samples);
		if (code)
			goto on_failure;
	}

	runtime->dma_area = (void *)devm_get_free_pages(dev, GFP_KERNEL,
							get_order(buffer_size));
	if (!runtime->dma_area) {
		code = -ENOMEM;
		goto on_failure;
	}

	runtime->dma_bytes = buffer_size;

on_failure:
	viosnd_ctl_msg_put(ctx, msg);

	return code;
}

static int viosnd_pcm_hw_free(struct snd_pcm_substream *substream)
{
	int code;
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);
	struct device *dev;
	struct snd_pcm_runtime *runtime = substream->runtime;

	if (!stream)
		return -EBADFD;

	code = wait_event_interruptible(stream->wait_xfer_state,
					!atomic_read(&stream->xfer_state));
	if (code)
		return code;

	dev = &stream->pcm->ctx->vdev->dev;

	if (stream->silence)
		devm_kfree(dev, stream->silence);

	if (runtime->dma_area)
		devm_free_pages(dev, (unsigned long)runtime->dma_area);

	stream->silence = NULL;
	runtime->dma_area = NULL;
	runtime->dma_bytes = 0;

	return 0;
}

static int viosnd_pcm_prepare(struct snd_pcm_substream *substream)
{
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);

	if (!stream)
		return -EBADFD;

	atomic64_set(&stream->hw_ptr, 0);
	stream->period_ptr = 0;
	stream->xfer_carry_frames = 0;
	atomic_set(&stream->xfer_state, PCM_XFER_DISABLED);

	return viosnd_pcm_send_generic(stream, VIRTIO_SND_R_PCM_PREPARE,
				       GFP_KERNEL, 1000);
}

static int viosnd_pcm_trigger(struct snd_pcm_substream *substream, int command)
{
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);
	u32 request_code;

	if (!stream)
		return -EBADFD;

	switch (command) {
	case SNDRV_PCM_TRIGGER_START: {
		u64 ns = pcm_xfer_ms * NSEC_PER_MSEC;

		atomic_inc(&stream->xfer_state); /* PCM_XFER_ENABLED */

		/*
		 * Use silence as prebuffed frames due to following reasons:
		 *   1) to avoid steep increase of hardware pointer at the
		 *      start of a substream,
		 *   2) to take into account possible lack of frames in hardware
		 *      buffer.
		 */
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			struct snd_pcm_runtime *runtime = substream->runtime;
			snd_pcm_sframes_t silence_size =
				pcm_target_ms * (runtime->rate / MSEC_PER_SEC);

			/* silence: PCM_XFER_PENDING */
			atomic_inc(&stream->xfer_state);

			viosnd_pcm_silence(stream, silence_size, GFP_ATOMIC);
		}

		stream->xfer_start_ns = ktime_get_raw_ns();
		stream->xfer_carry_ns = 0;

		hrtimer_start(&stream->hrt, ns_to_ktime(ns), HRTIMER_MODE_REL);

		request_code = VIRTIO_SND_R_PCM_START;

		break;
	}
	case SNDRV_PCM_TRIGGER_STOP: {
		atomic_dec(&stream->xfer_state); /* PCM_XFER_DISABLED */

		hrtimer_try_to_cancel(&stream->hrt);

		request_code = VIRTIO_SND_R_PCM_STOP;

		break;
	}
	default: {
		return -EINVAL;
	}
	}

	return viosnd_pcm_send_generic(stream, request_code, GFP_ATOMIC, 0);
}

static snd_pcm_uframes_t viosnd_pcm_pointer(struct snd_pcm_substream *substream)
{
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);
	snd_pcm_uframes_t hw_ptr;

	if (!stream)
		return 0;

	hw_ptr = (snd_pcm_uframes_t)atomic64_read(&stream->hw_ptr);

	return hw_ptr % substream->runtime->buffer_size;
}

static int viosnd_pcm_mmap(struct snd_pcm_substream *substream,
			   struct vm_area_struct *vma)
{
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);
	struct snd_pcm_runtime *runtime = substream->runtime;

	if (!stream)
		return -EBADFD;

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;

	return remap_pfn_range(vma, vma->vm_start,
			       virt_to_phys(runtime->dma_area) >> PAGE_SHIFT,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static const struct snd_pcm_ops viosnd_pcm_ops = {
	.open = viosnd_pcm_open,
	.close = viosnd_pcm_close,
	.ioctl = snd_pcm_lib_ioctl,
	.hw_params = viosnd_pcm_hw_params,
	.hw_free = viosnd_pcm_hw_free,
	.prepare = viosnd_pcm_prepare,
	.trigger = viosnd_pcm_trigger,
	.pointer = viosnd_pcm_pointer,
	.mmap = viosnd_pcm_mmap
};

static int viosnd_pcm_chmap_configure(struct viosnd_pcm_stream *stream)
{
	static const u8 positions[] = {
		[VIRTIO_SND_PCM_CH_NONE] = SNDRV_CHMAP_UNKNOWN,
		[VIRTIO_SND_PCM_CH_NA] = SNDRV_CHMAP_NA,
		[VIRTIO_SND_PCM_CH_MONO] = SNDRV_CHMAP_MONO,
		[VIRTIO_SND_PCM_CH_FL] = SNDRV_CHMAP_FL,
		[VIRTIO_SND_PCM_CH_FR] = SNDRV_CHMAP_FR,
		[VIRTIO_SND_PCM_CH_RL] = SNDRV_CHMAP_RL,
		[VIRTIO_SND_PCM_CH_RR] = SNDRV_CHMAP_RR,
		[VIRTIO_SND_PCM_CH_FC] = SNDRV_CHMAP_FC,
		[VIRTIO_SND_PCM_CH_LFE] = SNDRV_CHMAP_LFE,
		[VIRTIO_SND_PCM_CH_SL] = SNDRV_CHMAP_SL,
		[VIRTIO_SND_PCM_CH_SR] = SNDRV_CHMAP_SR,
		[VIRTIO_SND_PCM_CH_RC] = SNDRV_CHMAP_RC,
		[VIRTIO_SND_PCM_CH_FLC] = SNDRV_CHMAP_FLC,
		[VIRTIO_SND_PCM_CH_FRC] = SNDRV_CHMAP_FRC,
		[VIRTIO_SND_PCM_CH_RLC] = SNDRV_CHMAP_RLC,
		[VIRTIO_SND_PCM_CH_RRC] = SNDRV_CHMAP_RRC,
		[VIRTIO_SND_PCM_CH_FLW] = SNDRV_CHMAP_FLW,
		[VIRTIO_SND_PCM_CH_FRW] = SNDRV_CHMAP_FRW,
		[VIRTIO_SND_PCM_CH_FLH] = SNDRV_CHMAP_FLH,
		[VIRTIO_SND_PCM_CH_FCH] = SNDRV_CHMAP_FCH,
		[VIRTIO_SND_PCM_CH_FRH] = SNDRV_CHMAP_FRH,
		[VIRTIO_SND_PCM_CH_TC] = SNDRV_CHMAP_TC,
		[VIRTIO_SND_PCM_CH_TFL] = SNDRV_CHMAP_TFL,
		[VIRTIO_SND_PCM_CH_TFR] = SNDRV_CHMAP_TFR,
		[VIRTIO_SND_PCM_CH_TFC] = SNDRV_CHMAP_TFC,
		[VIRTIO_SND_PCM_CH_TRL] = SNDRV_CHMAP_TRL,
		[VIRTIO_SND_PCM_CH_TRR] = SNDRV_CHMAP_TRR,
		[VIRTIO_SND_PCM_CH_TRC] = SNDRV_CHMAP_TRC,
		[VIRTIO_SND_PCM_CH_TFLC] = SNDRV_CHMAP_TFLC,
		[VIRTIO_SND_PCM_CH_TFRC] = SNDRV_CHMAP_TFRC,
		[VIRTIO_SND_PCM_CH_TSL] = SNDRV_CHMAP_TSL,
		[VIRTIO_SND_PCM_CH_TSR] = SNDRV_CHMAP_TSR,
		[VIRTIO_SND_PCM_CH_LLFE] = SNDRV_CHMAP_LLFE,
		[VIRTIO_SND_PCM_CH_RLFE] = SNDRV_CHMAP_RLFE,
		[VIRTIO_SND_PCM_CH_BC] = SNDRV_CHMAP_BC,
		[VIRTIO_SND_PCM_CH_BLC] = SNDRV_CHMAP_BLC,
		[VIRTIO_SND_PCM_CH_BRC] = SNDRV_CHMAP_BRC
	};

	int code;
	struct viosnd_ctx *ctx = stream->pcm->ctx;
	struct virtio_device *vdev = ctx->vdev;
	struct device *dev = &vdev->dev;
	struct snd_pcm_chmap_elem *chmaps;
	struct viosnd_msg *msg;
	struct virtio_snd_pcm_query_chmap *request;
	struct virtio_snd_pcm_chmap_info *response;
	u8 chmap_id;

	chmaps = devm_kzalloc(dev, sizeof(*chmaps) * (stream->nchmaps + 1),
			      GFP_KERNEL);
	if (!chmaps)
		return -ENOMEM;

	msg = viosnd_ctl_msg_get(ctx, sizeof(*request), sizeof(*response),
				 GFP_KERNEL, 1000);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	request = (struct virtio_snd_pcm_query_chmap *)msg->request;

	request->hdr.code = cpu_to_virtio32(vdev, VIRTIO_SND_R_PCM_QUERY_CHMAP);
	request->pcm_id = stream->pcm->pcm->device;
	request->stream_type =
		(stream->substream->stream == SNDRV_PCM_STREAM_PLAYBACK) ?
			VIRTIO_SND_PCM_T_PLAYBACK :
			VIRTIO_SND_PCM_T_CAPTURE;

	response = (struct virtio_snd_pcm_chmap_info *)msg->response;

	for (chmap_id = 0; chmap_id < stream->nchmaps; ++chmap_id) {
		struct snd_pcm_chmap_elem *chmap = chmaps + chmap_id;
		u16 nchannels;
		u16 i;

		request->chmap_id = chmap_id;

		memset(response, 0, sizeof(*response));

		code = viosnd_ctl_msg_send(ctx, msg, 1000);
		if (code)
			goto on_failure;

		switch (response->type) {
		case VIRTIO_SND_PCM_CHMAP_FIXED:
		case VIRTIO_SND_PCM_CHMAP_VARIABLE:
		case VIRTIO_SND_PCM_CHMAP_PAIRED:
		{
			nchannels = le16_to_cpu(response->nchannels);
			if (nchannels > ARRAY_SIZE(chmap->map))
				nchannels = ARRAY_SIZE(chmap->map);

			chmap->channels = nchannels;

			break;
		}
		default:
		{
			code = -EINVAL;
			goto on_failure;
		}
		}

		for (i = 0; i < nchannels; ++i) {
			u8 position = response->positions[i];

			if (position > ARRAY_SIZE(positions)) {
				code = -EINVAL;
				goto on_failure;
			}

			chmap->map[i] = positions[position];
		}
	}

	code = snd_pcm_add_chmap_ctls(stream->pcm->pcm,
				      stream->substream->stream, chmaps,
				      stream->hw.channels_max, 0, NULL);

on_failure:
	viosnd_ctl_msg_put(ctx, msg);

	return code;
}

static struct viosnd_pcm_stream *
viosnd_pcm_stream_configure(struct viosnd_pcm *pcm,
			    struct virtio_snd_pcm_stream_desc *desc)
{
	static const struct {
		u32 vio_bit;
		unsigned int alsa_fmt;
	} fmtmap[] = {
		{ VIRTIO_SND_PCM_FMTBIT_S8, SNDRV_PCM_FORMAT_S8 },
		{ VIRTIO_SND_PCM_FMTBIT_U8, SNDRV_PCM_FORMAT_U8 },
		{ VIRTIO_SND_PCM_FMTBIT_S16, SNDRV_PCM_FORMAT_S16 },
		{ VIRTIO_SND_PCM_FMTBIT_U16, SNDRV_PCM_FORMAT_U16 },
		{ VIRTIO_SND_PCM_FMTBIT_S32, SNDRV_PCM_FORMAT_S32 },
		{ VIRTIO_SND_PCM_FMTBIT_U32, SNDRV_PCM_FORMAT_U32 },
		{ VIRTIO_SND_PCM_FMTBIT_FLOAT, SNDRV_PCM_FORMAT_FLOAT },
		{ VIRTIO_SND_PCM_FMTBIT_FLOAT64, SNDRV_PCM_FORMAT_FLOAT64 }
	};

	static const struct {
		u32 vio_bit;
		u64 alsa_bit;
		unsigned int rate;
	} ratemap[] = {
		{ VIRTIO_SND_PCM_RATEBIT_8000, SNDRV_PCM_RATE_8000, 8000 },
		{ VIRTIO_SND_PCM_RATEBIT_11025, SNDRV_PCM_RATE_11025, 11025 },
		{ VIRTIO_SND_PCM_RATEBIT_16000, SNDRV_PCM_RATE_16000, 16000 },
		{ VIRTIO_SND_PCM_RATEBIT_22050, SNDRV_PCM_RATE_22050, 22050 },
		{ VIRTIO_SND_PCM_RATEBIT_32000, SNDRV_PCM_RATE_32000, 32000 },
		{ VIRTIO_SND_PCM_RATEBIT_44100, SNDRV_PCM_RATE_44100, 44100 },
		{ VIRTIO_SND_PCM_RATEBIT_48000, SNDRV_PCM_RATE_48000, 48000 },
		{ VIRTIO_SND_PCM_RATEBIT_64000, SNDRV_PCM_RATE_64000, 64000 },
		{ VIRTIO_SND_PCM_RATEBIT_88200, SNDRV_PCM_RATE_88200, 88200 },
		{ VIRTIO_SND_PCM_RATEBIT_96000, SNDRV_PCM_RATE_96000, 96000 },
		{ VIRTIO_SND_PCM_RATEBIT_176400, SNDRV_PCM_RATE_176400,
		  176400 },
		{ VIRTIO_SND_PCM_RATEBIT_192000, SNDRV_PCM_RATE_192000, 192000 }
	};

	struct device *dev = &pcm->ctx->vdev->dev;
	struct viosnd_pcm_stream *stream;
	unsigned int i;
	u32 formats;
	u32 rates;
	u32 sample_min = 0;
	u32 sample_max = 0;
	u32 frames;
	u32 frame_size;

	stream = devm_kzalloc(dev, sizeof(*stream), GFP_KERNEL);
	if (!stream)
		return ERR_PTR(-ENOMEM);

	stream->pcm = pcm;
	stream->nchmaps = desc->nchmaps;

	hrtimer_init(&stream->hrt, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	stream->hrt.function = viosnd_pcm_timer_cb;

	init_waitqueue_head(&stream->wait_xfer_state);

	stream->hw.info =
		(SNDRV_PCM_INFO_MMAP |
		 SNDRV_PCM_INFO_MMAP_VALID |
		 SNDRV_PCM_INFO_BATCH |
		 SNDRV_PCM_INFO_BLOCK_TRANSFER |
		 SNDRV_PCM_INFO_INTERLEAVED |
		 SNDRV_PCM_INFO_NO_PERIOD_WAKEUP);

	formats = le32_to_cpu(desc->formats);

	for (i = 0; i < ARRAY_SIZE(fmtmap); ++i)
		if (formats & fmtmap[i].vio_bit) {
			unsigned int alsa_fmt = fmtmap[i].alsa_fmt;
			int size = snd_pcm_format_physical_width(alsa_fmt) / 8;

			if (!sample_min || sample_min > size)
				sample_min = size;

			if (sample_max < size)
				sample_max = size;

			stream->hw.formats |= (1ULL << alsa_fmt);
		}

	if (!stream->hw.formats) {
		dev_err(dev, "No supported formats found");
		return ERR_PTR(-EINVAL);
	}

	rates = le32_to_cpu(desc->rates);

	for (i = 0; i < ARRAY_SIZE(ratemap); ++i)
		if (rates & ratemap[i].vio_bit) {
			if (stream->hw.rate_min == 0 ||
			    stream->hw.rate_min > ratemap[i].rate)
				stream->hw.rate_min = ratemap[i].rate;

			if (stream->hw.rate_max < ratemap[i].rate)
				stream->hw.rate_max = ratemap[i].rate;

			stream->hw.rates |= ratemap[i].alsa_bit;
		}

	if (!stream->hw.rates) {
		dev_err(dev, "No supported rates found");
		return ERR_PTR(-EINVAL);
	}

	stream->hw.channels_min = desc->channels_min;
	stream->hw.channels_max = desc->channels_max;

	/*
	 * Formats, rates and channels are taken from a device configuration
	 * reported by virtio device side. All other hardware descriptor fields
	 * are either some rational assumptions or derived from two module
	 * parameters:
	 *   - pcm_buffer_ms
	 *   - pcm_xfer_ms
	 */
	stream->hw.periods_min = 2;

	/*
	 * buffer_bytes_max is {pcm_buffer_ms} for maximum possible combination
	 * of (format, channels, rate) tuples rounded to a page boundary.
	 */
	frame_size = sample_max * stream->hw.channels_max;
	frames = pcm_buffer_ms * (stream->hw.rate_max / MSEC_PER_SEC);
	stream->hw.buffer_bytes_max =
		(frame_size * frames + PAGE_SIZE - 1) & -PAGE_SIZE;

	/*
	 * period_bytes_max is {pcm_buffer_ms} for maximum possible combination
	 * of (format, channels, rate) tuples divided by {periods_min} value.
	 */
	stream->hw.period_bytes_max =
		(frame_size * frames) / stream->hw.periods_min;

	/*
	 * period_bytes_min is {pcm_xfer_ms} for minimum possible combination
	 * of (format, channels, rate) tuples.
	 */
	frame_size = sample_min * desc->channels_min;
	frames = pcm_xfer_ms * (stream->hw.rate_min / MSEC_PER_SEC);
	stream->hw.period_bytes_min = frame_size * frames;

	/*
	 * periods_max is {pcm_buffer_ms} for minimum possible combination of
	 * (format, channels, rate) tuples divided by {period_bytes_min} value.
	 */
	frames = pcm_buffer_ms * (stream->hw.rate_min / MSEC_PER_SEC);
	stream->hw.periods_max =
		(frame_size * frames) / stream->hw.period_bytes_min;

	return stream;
}

static int viosnd_pcm_configure(struct viosnd_ctx *ctx,
				struct virtio_snd_pcm_desc *desc)
{
	static int typemap[] = {
		[VIRTIO_SND_PCM_T_PLAYBACK] = SNDRV_PCM_STREAM_PLAYBACK,
		[VIRTIO_SND_PCM_T_CAPTURE] = SNDRV_PCM_STREAM_CAPTURE
	};
	int code;
	struct device *dev = &ctx->vdev->dev;
	struct viosnd_pcm *pcm;
	struct virtio_snd_pcm_stream_desc *stream_desc;
	unsigned int i;
	unsigned int npbs = 0;
	unsigned int ncps = 0;
	u8 pcm_id;

	if (desc->length != sizeof(struct virtio_snd_pcm_desc))
		return -EINVAL;

	pcm = devm_kzalloc(dev, sizeof(*pcm), GFP_KERNEL);
	if (!pcm)
		return -ENOMEM;

	pcm_id = desc->pcm_id;

	if (!viosnd_activate_queue(ctx, VIRTIO_SND_FN_PCM, pcm_id, 0, pcm)) {
		dev_err(dev, "No PCM data queue");
		return -ENODEV;
	}

	pcm->ctx = ctx;
	spin_lock_init(&pcm->lock);

	stream_desc = (struct virtio_snd_pcm_stream_desc *)(desc + 1);

	for (i = 0; i < desc->nstreams; i++, stream_desc++) {
		bool valid =
			(stream_desc->type == VIRTIO_SND_DESC_PCM_STREAM) &&
			(stream_desc->length ==
			 sizeof(struct virtio_snd_pcm_stream_desc)) &&
			((stream_desc->stream_type ==
			  VIRTIO_SND_PCM_T_PLAYBACK) ||
			 (stream_desc->stream_type ==
			  VIRTIO_SND_PCM_T_CAPTURE)) &&
			!pcm->streams[stream_desc->stream_type];

		if (!valid) {
			dev_err(dev, "Malformed PCM stream configuration");
			return -EINVAL;
		}

		pcm->streams[stream_desc->stream_type] =
			viosnd_pcm_stream_configure(pcm, stream_desc);
		if (IS_ERR(pcm->streams[stream_desc->stream_type]))
			return PTR_ERR(pcm->streams[stream_desc->stream_type]);
	}

	if (pcm->streams[VIRTIO_SND_PCM_T_PLAYBACK])
		npbs = 1;

	if (pcm->streams[VIRTIO_SND_PCM_T_CAPTURE])
		ncps = 1;

	if (!npbs && !ncps) {
		dev_err(dev, "No PCM stream found");
		return -EINVAL;
	}

	code = snd_pcm_new(ctx->card, "virtio_snd", pcm_id, npbs, ncps,
			   &pcm->pcm);
	if (code) {
		dev_err(dev, "snd_pcm_new failed: %d", code);
		return code;
	}

	pcm->pcm->info_flags = 0;
	pcm->pcm->dev_class = SNDRV_PCM_CLASS_GENERIC;
	pcm->pcm->dev_subclass = SNDRV_PCM_SUBCLASS_GENERIC_MIX;
	strcpy(pcm->pcm->name, "VirtIO Sound Card PCM");
	pcm->pcm->private_data = pcm;

	for (i = 0; i < ARRAY_SIZE(typemap); ++i) {
		struct viosnd_pcm_stream *stream = pcm->streams[i];

		if (!stream)
			continue;

		snd_pcm_set_ops(pcm->pcm, typemap[i], &viosnd_pcm_ops);

		stream->substream = pcm->pcm->streams[typemap[i]].substream;

		if (stream->nchmaps) {
			if (viosnd_pcm_chmap_configure(stream)) {
				dev_err(dev, "Failed to configure channel map");
				return -EINVAL;
			}
		}
	}

	return sizeof(struct virtio_snd_pcm_desc) +
	       sizeof(struct virtio_snd_pcm_stream_desc) * desc->nstreams;
}

static int viosnd_card_configure(struct viosnd_ctx *ctx)
{
	static int g_ndevices;
	static int g_indexes[SNDRV_CARDS] = SNDRV_DEFAULT_IDX;
	static char *g_ids[SNDRV_CARDS] = SNDRV_DEFAULT_STR;
	static struct snd_device_ops ops = { 0 };

	int code;
	struct virtio_device *vdev = ctx->vdev;
	struct device *dev = &vdev->dev;
	struct viosnd_msg *msg;
	struct virtio_snd_base_configuration *response;
	u32 data_length;
	u8 *data;

	if (g_ndevices >= SNDRV_CARDS)
		return -ENODEV;

	msg = viosnd_ctl_msg_get(ctx, sizeof(struct virtio_snd_hdr),
				 sizeof(*response), GFP_KERNEL, 1000);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	msg->request->code = cpu_to_virtio32(vdev, VIRTIO_SND_R_BASE_GET_CFG);

	code = viosnd_ctl_msg_send(ctx, msg, 1000);
	if (code != 0) {
		dev_err(dev, "Could not get device configuration: %d", code);
		goto on_failure;
	}

	code = snd_card_new(dev, g_indexes[g_ndevices], g_ids[g_ndevices],
			    THIS_MODULE, 0, &ctx->card);
	if (code < 0)
		goto on_failure;

	strlcpy(ctx->card->id, "viosnd", sizeof(ctx->card->id));
	strlcpy(ctx->card->driver, "virtio_snd", sizeof(ctx->card->driver));
	strlcpy(ctx->card->shortname, "VIOSND", sizeof(ctx->card->shortname));
	strlcpy(ctx->card->longname, "VirtIO Sound Card",
		sizeof(ctx->card->longname));
	ctx->card->private_data = ctx;

	code = snd_device_new(ctx->card, SNDRV_DEV_LOWLEVEL, ctx, &ops);
	if (code < 0)
		goto on_failure;

	response = (struct virtio_snd_base_configuration *)msg->response;

	data_length = response->length;
	data = response->data;

	while (data_length != 0) {
		struct virtio_snd_desc *desc = (struct virtio_snd_desc *)data;
		u32 desc_length;

		switch (desc->type) {
		case VIRTIO_SND_DESC_PCM: {
			struct virtio_snd_pcm_desc *pcm_desc =
				(struct virtio_snd_pcm_desc *)desc;

			code = viosnd_pcm_configure(ctx, pcm_desc);
			if (code < 0)
				goto on_failure;

			desc_length = code;

			break;
		}
		default: {
			desc_length = desc->length;

			break;
		}
		}

		if (desc_length > data_length)
			desc_length = data_length;

		data_length -= desc_length;
		data += desc_length;
	}

	code = snd_card_register(ctx->card);
	if (code < 0)
		goto on_failure;

	g_ndevices++;

	code = 0; /* success */

on_failure:
	viosnd_ctl_msg_put(ctx, msg);

	return code;
}

static int viosnd_probe(struct virtio_device *vdev)
{
	int code;
	struct device *dev = &vdev->dev;
	struct viosnd_ctx *ctx;
	unsigned int i;
	struct virtqueue **queues;
	vq_callback_t **callbacks;
	const char **names;
	struct irq_affinity affinity = {
		0,
	};

	if (!vdev->config->get) {
		dev_err(dev, "Config access disabled");
		return -EINVAL;
	}

	ctx = devm_kzalloc(dev, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->vdev = vdev;
	vdev->priv = ctx;

	virtio_cread(vdev, struct virtio_snd_config, nqueues, &ctx->nqueues);

	if (!ctx->nqueues || ctx->nqueues > 255) {
		dev_err(dev, "Invalid number of virtual queues: %u",
			ctx->nqueues);
		return -EINVAL;
	}

	ctx->queues = devm_kcalloc(dev, ctx->nqueues, sizeof(*ctx->queues),
				   GFP_KERNEL);
	if (!ctx->queues)
		return -ENOMEM;

	for (i = 0; i < ctx->nqueues; ++i) {
		struct virtio_snd_queue_info *info = &ctx->queues[i].info;
		unsigned int offset =
			sizeof(struct virtio_snd_config) + i * sizeof(*info);

		virtio_cread_bytes(vdev, offset, info, sizeof(*info));

		info->function = virtio32_to_cpu(vdev, info->function);
	}

	queues = devm_kcalloc(dev, ctx->nqueues, sizeof(*queues), GFP_KERNEL);
	if (!queues)
		return -ENOMEM;

	callbacks = devm_kcalloc(dev, ctx->nqueues, sizeof(*callbacks),
				 GFP_KERNEL);
	if (!callbacks)
		return -ENOMEM;

	names = devm_kcalloc(dev, ctx->nqueues, sizeof(*names), GFP_KERNEL);
	if (!names)
		return -ENOMEM;

	for (i = 0; i < ctx->nqueues; ++i) {
		switch (ctx->queues[i].info.function) {
		case VIRTIO_SND_FN_BASE:
			callbacks[i] = viosnd_ctl_notify_cb;
			names[i] = "viosnd-ctl";
			break;
		case VIRTIO_SND_FN_PCM:
			callbacks[i] = viosnd_pcm_notify_cb;
			names[i] = "viosnd-pcm";
			break;
		}
	}

	code = virtio_find_vqs(vdev, ctx->nqueues, queues, callbacks, names,
			       &affinity);
	if (code != 0)
		return code;

	for (i = 0; i < ctx->nqueues; ++i) {
		ctx->queues[i].vqueue = queues[i];

		virtqueue_disable_cb(queues[i]);
	}

	devm_kfree(dev, callbacks);
	devm_kfree(dev, names);

	if (!viosnd_activate_queue(ctx, VIRTIO_SND_FN_BASE, 0, 0, ctx)) {
		dev_err(dev, "No control queue");
		return -ENODEV;
	}

	ctx->msg_count =
		virtqueue_get_vring_size(viosnd_find_vqueue(ctx, ctx)) / 2;

	spin_lock_init(&ctx->lock);
	init_waitqueue_head(&ctx->wait_available);

	virtio_device_ready(vdev);

	return viosnd_card_configure(ctx);
}

static void viosnd_remove(struct virtio_device *vdev)
{
	struct viosnd_ctx *ctx = vdev->priv;

	if (!ctx)
		return;

	if (ctx->card)
		snd_card_free(ctx->card);

	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);

	vdev->priv = NULL;
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_SOUND, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver viosnd_driver = {
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = viosnd_probe,
	.remove = viosnd_remove,
/* TODO: device power management */
#ifdef CONFIG_PM_SLEEP
	.freeze = NULL,
	.restore = NULL,
#endif
};

static int __init init(void)
{
	if (!pcm_buffer_ms) {
		pr_err("virtio-snd: pcm_buffer_ms can not be zero\n");
		return -EINVAL;
	}

	if (!pcm_target_ms) {
		pr_err("virtio-snd: pcm_target_ms can not be zero\n");
		return -EINVAL;
	}

	if (!pcm_xfer_ms) {
		pr_err("virtio-snd: pcm_xfer_ms can not be zero\n");
		return -EINVAL;
	}

	if (pcm_buffer_ms < pcm_target_ms) {
		pr_err("virtio-snd: pcm_buffer_ms must be >= pcm_target_ms\n");
		return -EINVAL;
	}

	if (pcm_target_ms < pcm_xfer_ms) {
		pr_err("virtio-snd: pcm_target_ms must be >= pcm_xfer_ms\n");
		return -EINVAL;
	}

	pr_info("virtio-snd: set PCM function parameters: "
		"pcm_buffer_ms=%u pcm_target_ms=%u pcm_xfer_ms=%u\n",
		pcm_buffer_ms, pcm_target_ms, pcm_xfer_ms);

	return register_virtio_driver(&viosnd_driver);
}
module_init(init);

static void __exit fini(void)
{
	unregister_virtio_driver(&viosnd_driver);
}
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio sound card driver");
MODULE_LICENSE("GPL");
