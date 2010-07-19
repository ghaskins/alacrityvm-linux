/*
 * venetdev - A 802.x virtual network device based on the VBUS/IOQ interface
 *
 * Copyright (C) 2009 Novell, Gregory Haskins <ghaskins@novell.com>
 *
 * Derived from the SNULL example from the book "Linux Device Drivers" by
 * Alessandro Rubini, Jonathan Corbet, and Greg Kroah-Hartman, published
 * by O'Reilly & Associates.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/wait.h>

#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ioq.h>
#include <linux/vbus.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/mmu_context.h>
#include <linux/ktime.h>
#include <linux/highmem.h>

#include "venetdevice.h"

#include <linux/in6.h>
#include <asm/checksum.h>

MODULE_AUTHOR("Gregory Haskins");
MODULE_LICENSE("GPL");

#undef PDEBUG             /* undef it, just in case */
#ifdef VENETDEV_DEBUG
#  define PDEBUG(fmt, args...) printk(KERN_DEBUG "venet-tap: " fmt, ## args)
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

static int maxcount = 2048;
module_param(maxcount, int, 0600);
MODULE_PARM_DESC(maxcount, "maximum size for rx/tx ioq ring");

/* This must be defined as the largest event we can generate */
#define EVQ_EVSIZE sizeof(struct venet_event_txc)

#define PMTD_POOL_ID 100
#define EVQ_DPOOL_ID 101
#define EVQ_QUEUE_ID 102
#define L4RO_DPOOL_ID 103
#define L4RO_PAGEQ_ID 104

static void venetdev_tx_isr(struct ioq_notifier *notifier);
static void venetdev_txc_notifier(struct ioq_notifier *notifier);
static int venetdev_rx_thread(void *__priv);
static int venetdev_tx_thread(void *__priv);

static void evq_send_linkstatus(struct venetdev *priv, bool status);

struct _venetdev_skb {
	struct venetdev *priv;
	u64              cookie;
	struct list_head list;
};

static int
venetdev_queue_init(struct venetdev_queue *q,
		    struct vbus_shm *shm,
		    struct shm_signal *signal,
		    void (*func)(struct ioq_notifier *))
{
	struct ioq *ioq;
	int ret;

	if (q->queue)
		return -EEXIST;

	/* FIXME: make maxcount a tunable */
	ret = vbus_shm_ioq_attach(shm, signal, maxcount, &ioq);
	if (ret < 0)
		return ret;

	q->queue = ioq;

	if (func) {
		q->notifier.signal = func;
		q->queue->notifier = &q->notifier;
	}

	return 0;
}

static void
venetdev_queue_release(struct venetdev_queue *q)
{
	if (!q->queue)
		return;

	ioq_put(q->queue);
	q->queue = NULL;
}

static int
venetdev_pmtd_init(struct venetdev *priv,
		   struct vbus_shm *shm, struct shm_signal *signal)
{
	if (signal || !priv->vbus.pmtd.enabled)
		return -EINVAL;

	if (priv->vbus.pmtd.shm)
		return -EEXIST;

	priv->vbus.pmtd.shm = shm;

	return 0;
}

static int
venetdev_evq_dpool_init(struct venetdev *priv,
			struct vbus_shm *shm, struct shm_signal *signal)
{
	if (signal || !priv->vbus.evq.enabled)
		return -EINVAL;

	if (priv->vbus.evq.shm)
		return -EEXIST;

	priv->vbus.evq.shm = shm;

	return 0;
}

static int
venetdev_evq_queue_init(struct venetdev *priv, struct vbus_shm *shm,
			struct shm_signal *signal,
			void (*func)(struct ioq_notifier *))
{
	int ret;

	if (!signal || !priv->vbus.evq.shm)
		return -EINVAL;

	if (priv->vbus.evq.queue.queue)
		return -EEXIST;

	ret = venetdev_queue_init(&priv->vbus.evq.queue, shm, signal, func);
	if (ret < 0)
		return ret;

	/*
	 * Validate that the dpool size is sane w.r.t. the number of
	 * descriptors in the ring
	 */
	if (ioq_size(priv->vbus.evq.queue.queue)*EVQ_EVSIZE
	    != priv->vbus.evq.shm->len) {
		ioq_put(priv->vbus.evq.queue.queue);
		priv->vbus.evq.queue.queue = NULL;
		return -EINVAL;
	}

	return 0;
}

static int
venetdev_l4ro_dpool_init(struct venetdev *priv,
			struct vbus_shm *shm, struct shm_signal *signal)
{
	if (signal || !priv->vbus.l4ro.available)
		return -EINVAL;

	if (priv->vbus.l4ro.shm)
		return -EEXIST;

	/*
	 * Validate that the dpool size is sane w.r.t. the number of
	 * descriptors in the ring
	 */
	if (shm->len > maxcount*MAX_VSG_DESC_SIZE)
		return -EINVAL;

	priv->vbus.l4ro.shm = shm;

	return 0;
}


/* Assumes priv->lock is held */
static void
venetdev_txq_notify_inc(struct venetdev *priv)
{
	priv->netif.txq.irqdepth++;
	if (priv->netif.txq.irqdepth == 1 && priv->vbus.link)
		ioq_notify_enable(priv->vbus.txq.queue, 0);
}

/* Assumes priv->lock is held */
static void
venetdev_txq_notify_dec(struct venetdev *priv)
{
	BUG_ON(!priv->netif.txq.irqdepth);
	priv->netif.txq.irqdepth--;
	if (!priv->netif.txq.irqdepth && priv->vbus.link)
		ioq_notify_disable(priv->vbus.txq.queue, 0);
}

/*
 *----------------------------------------------------------------------
 * netif link
 *----------------------------------------------------------------------
 */

int
venetdev_open(struct venetdev *priv)
{
	unsigned long flags;

	BUG_ON(priv->netif.link);

	/*
	 * We need rx-polling to be done in process context, and we want
	 * ingress processing to occur independent of the producer thread
	 * to maximize multi-core distribution.  Since the built in NAPI uses a
	 * softirq, we cannot guarantee this wont call us back in interrupt
	 * context, so we cant use it.  And both a work-queue or softirq
	 * solution would tend to process requests on the same CPU as the
	 * producer.  Therefore, we create a special thread to handle ingress.
	 *
	 * The downside to this type of approach is that we may still need to
	 * ctx-switch to the NAPI polling thread (presumably running on the same
	 * core as the rx-thread) by virtue of the netif_rx() backlog mechanism.
	 * However, this can be mitigated by the use of netif_rx_ni().
	 */
	priv->rxthread = kthread_create(venetdev_rx_thread, priv,
					"%s-rx", priv->netif.dev->name);

	priv->txthread = kthread_create(venetdev_tx_thread, priv,
					"%s-tx", priv->netif.dev->name);

	spin_lock_irqsave(&priv->lock, flags);

	priv->netif.link = true;

	if (!priv->vbus.link)
		netif_carrier_off(priv->netif.dev);

	spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

int
venetdev_netdev_open(struct net_device *dev)
{
	struct venetdev *priv = netdev_priv(dev);

	return venetdev_open(priv);
}

int
venetdev_stop(struct venetdev *priv)
{
	unsigned long flags;
	int needs_stop = false;

	spin_lock_irqsave(&priv->lock, flags);

	if (priv->netif.link) {
		needs_stop = true;
		priv->netif.link = false;
	}

	/* FIXME: free priv->netif.txq */

	spin_unlock_irqrestore(&priv->lock, flags);

	if (needs_stop) {
		kthread_stop(priv->rxthread);
		priv->rxthread = NULL;

		kthread_stop(priv->txthread);
		priv->txthread = NULL;
	}

	return 0;
}

int
venetdev_netdev_stop(struct net_device *dev)
{
	struct venetdev *priv = netdev_priv(dev);

	return venetdev_stop(priv);
}

/*
 * Configuration changes (passed on by ifconfig)
 */
int
venetdev_netdev_config(struct net_device *dev, struct ifmap *map)
{
	if (dev->flags & IFF_UP) /* can't act on a running interface */
		return -EBUSY;

	/* Don't allow changing the I/O address */
	if (map->base_addr != dev->base_addr) {
		printk(KERN_WARNING "venetdev: Can't change I/O address\n");
		return -EOPNOTSUPP;
	}

	/* ignore other fields */
	return 0;
}

int
venetdev_change_mtu(struct net_device *dev, int new_mtu)
{
	dev->mtu = new_mtu;

	return 0;
}

/*
 * ---------------------------
 * EVQ support
 * ---------------------------
 */

static bool
evq_send_event(struct venetdev *priv, struct venet_event_header *header,
	       bool signal)
{
	struct ioq_iterator         iter;
	struct ioq                 *ioq = priv->vbus.evq.queue.queue;
	int                         ret;
	size_t                      offset;
	void                       *ptr;
	unsigned long               flags;

	BUG_ON(!priv->vbus.evq.enabled);
	BUG_ON(!priv->vbus.evq.queue.queue);
	BUG_ON(header->size > EVQ_EVSIZE);

	spin_lock_irqsave(&priv->vbus.evq.lock, flags);

	ret = ioq_iter_init(ioq, &iter, ioq_idxtype_inuse, 0);
	BUG_ON(ret < 0);

	ret = ioq_iter_seek(&iter, ioq_seek_tail, 0, 0);
	BUG_ON(ret < 0);

	if (!iter.desc->sown) {
		spin_unlock_irqrestore(&priv->vbus.evq.lock, flags);
		return true; /* backpressure */
	}

	offset = (size_t)le64_to_cpu(iter.desc->ptr);
	ptr = priv->vbus.evq.shm->ptr + offset;

	if ((offset + header->size) > priv->vbus.evq.shm->len) {
		SHM_SIGNAL_FAULT(ioq->signal, "offset overrun: %d+%d > %d\n",
				 offset, header->size, priv->vbus.evq.shm->len);
		goto out;
	}

	memcpy(ptr, header, header->size);

	ret = ioq_iter_push(&iter, 0);
	BUG_ON(ret < 0);

out:
	spin_unlock_irqrestore(&priv->vbus.evq.lock, flags);

	if (signal)
		ioq_signal(ioq, 0);

	return false;
}

static void
evq_send_linkstatus(struct venetdev *priv, bool status)
{
	struct venet_event_linkstate event = {
		.header = {
			.size = sizeof(struct venet_event_linkstate),
			.id = VENET_EVENT_LINKSTATE,
		},
		.state = status ? 1 : 0,
	};

	if (priv->vbus.evq.linkstate)
		evq_send_event(priv, &event.header, true);
}

static bool
evq_send_txc(struct venetdev *priv, u64 cookie)
{
	struct venet_event_txc event = {
		.header = {
			.size = sizeof(struct venet_event_txc),
			.id = VENET_EVENT_TXC,
		},
		.txqid = 0, /* we do not yet support multi-queue */
		.cookie = cookie,
	};

	return evq_send_event(priv, &event.header, false);
}

/*
 * ---------------------------
 * Scatter-Gather support
 * ---------------------------
 */

/* assumes reference to priv->vbus.conn held */
static struct venet_sg *
venetdev_sg_desc_get(struct venetdev *priv, void *ptr, int len)
{
	struct venet_sg *vsg = (struct venet_sg *)priv->vbus.sg.buf;
	int total = 0;
	int ret;
	int i;

	PDEBUG("desc: %p/%d\n", ptr, len);

	if (unlikely(len < sizeof(*vsg) || len > MAX_VSG_DESC_SIZE)) {
		PDEBUG("invalid len: %d\n", len);
		return NULL;
	}

	/*
	 * SG is enabled, so we need to pull in the venet_sg
	 * header before we can interpret the rest of the
	 * packet
	 */

	if (priv->vbus.pmtd.shm) {
		/* 'ptr' is an offset into our PMTD pool when pmtd is enabled */
		size_t offset = (size_t)ptr;
		void *_ptr = priv->vbus.pmtd.shm->ptr + offset;

		if ((offset + len) > priv->vbus.pmtd.shm->len) {
			PDEBUG("offset overrun: %d+%d > %d\n",
			       offset, len, priv->vbus.pmtd.shm->len);
			return NULL;
		}

		/*
		 * We copy the descriptor here even though its technically
		 * mapped to avoid the possibility that a malicious guest
		 * can alter the descriptor after we validate it
		 */
		memcpy((void *)vsg, _ptr, len);

	} else {
		struct vbus_memctx *ctx = priv->vbus.ctx;

		ret = ctx->ops->copy_from(ctx, vsg, ptr, len);
		if (ret) {
			PDEBUG("copy_from: EFAULT\n");
			return NULL;
		}
	}

	priv->vbus.sg.len = len;

	PDEBUG("pmtd-pool:%p, vsg=%p\n", priv->vbus.pmtd.shm->ptr, vsg);

	/*
	 * ---------------------------
	 * Validate all of the lengths
	 * ---------------------------
	 */

	if (len < VSG_DESC_SIZE(vsg->count)) {
		PDEBUG("%d < %d\n", len, VSG_DESC_SIZE(vsg->count));
		return NULL;
	}

	if (vsg->flags & VENET_SG_FLAG_GSO) {
		/* GSO packets shall not exceed 64k frames */
		if (vsg->len > 65536)
			return NULL;

	} else
		/*
		 * Non GSO type packets should be constrained by the MTU setting
		 * on the host
		 */
		if (vsg->len > (priv->netif.dev->mtu + ETH_HLEN))
			return NULL;

	/*
	 * We cannot support more fragments than our SKBs allow
	 */
	if (vsg->count > MAX_SKB_FRAGS)
		return NULL;

	PDEBUG("Importing %d bytes in %d segments\n", vsg->len, vsg->count);

	/*
	 * And finally, our total length computed from the IOV should
	 * match the submitted total length.
	 */
	for (i = 0; i < vsg->count; i++) {
		struct venet_iov *iov = &vsg->iov[i];

		PDEBUG("Segment %d: %d bytes\n", i, iov->len);
		total += iov->len;
	}

	if (total != vsg->len)
		return NULL;

	return vsg;
}

struct venet_sg_iterator {
	struct venet_sg    *vsg;
	struct vbus_memctx *ctx;
	int                 index;
	int                 offset;
	int                 pos;
};

static void
venet_sg_iter_init(struct venet_sg_iterator *iter,
		   struct venet_sg *vsg, struct vbus_memctx *ctx)
{
	memset(iter, 0, sizeof(*iter));
	iter->vsg = vsg;
	iter->ctx = ctx;
}

static void *
venet_sg_iter(struct venet_sg_iterator *iter, size_t *len)
{
	struct venet_iov *iov = &iter->vsg->iov[iter->index];
	int remain = iov->len - iter->offset;
	int consume = *len < remain ? *len : remain;
	void *ptr;

	if (iter->pos >= iter->vsg->len) {
		*len = 0;
		return NULL;
	}

	ptr = (void *)iov->ptr + iter->offset;
	*len = consume;

	iter->offset += consume;
	iter->pos    += consume;
	if (iter->offset == iov->len) {
		iter->index++;
		iter->offset = 0;
	}

	return ptr;
}

static int
venet_sg_iter_copy(struct venet_sg_iterator *iter, char *dst, size_t len)
{
	struct vbus_memctx *ctx = iter->ctx;
	int ret;

	while (len) {
		size_t bytestocopy = len;
		void *src = venet_sg_iter(iter, &bytestocopy);

		if (!src)
			return len;

		ret = ctx->ops->copy_from(ctx, dst, src, bytestocopy);
		if (ret)
			return -EFAULT;

		dst += bytestocopy;
		len -= bytestocopy;
	}

	return len;
}

static void venetdev_skb_release(struct sk_buff *skb);

static int
venetdev_sg_import_zc(struct venetdev *priv,
			struct venet_sg *vsg,
			struct sk_buff *skb)
{
	struct vbus_memctx *ctx = priv->vbus.ctx;
	struct venet_sg_iterator iter;
	struct scatterlist sgl[vsg->count];
	struct scatterlist *sg;
	struct _venetdev_skb *_skb;
	int maxoutstanding = ioq_size(priv->vbus.rxq.queue);
	int nr_addrs = 0;
	int i;
	int ret;

	/*
	 * We backpressure the queue (by sleeping) if we have too many
	 * outstanding packets.   The backpressure if relieved as the
	 * packets complete
	 */
	if (atomic_read(&priv->netif.rxq.outstanding) >= maxoutstanding) {
		wait_event(priv->netif.rxq.wq,
			   (atomic_read(&priv->netif.rxq.outstanding) < maxoutstanding));
	}

	venet_sg_iter_init(&iter, vsg, priv->vbus.ctx);

	/* First import the header */
	if (skb_headlen(skb)) {
		PDEBUG("SG: Importing %d byte header\n", skb_headlen(skb));

		ret = venet_sg_iter_copy(&iter, skb->data, skb_headlen(skb));
		if (ret) {
			kfree_skb(skb);
			return ret > 0 ? -EINVAL : ret;
		}
	}

	sg_init_table(sgl, vsg->count);

	/* And then any remaining payload is paged in */
	for_each_sg(sgl, sg, vsg->count, i) {
		size_t len = PAGE_SIZE;
		void *ptr;

		ptr = venet_sg_iter(&iter, &len);
		if (!ptr)
			break;

		sg_dma_address(sg) = (dma_addr_t)ptr;
		sg_dma_len(sg)     = len;

		nr_addrs++;
	}

	sg_mark_end(&sgl[nr_addrs-1]);

	ret = ctx->ops->sg_map(ctx, sgl, nr_addrs);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	for_each_sg(sgl, sg, nr_addrs, i) {
		skb_frag_t *f = &skb_shinfo(skb)->frags[i];

		f->page = sg_page(sg);

		f->page_offset = sg->offset;
		f->size        = sg->length;

		PDEBUG("SG: Importing %d byte page[%i]\n", f->size, i);

		skb->data_len += f->size;
		skb->len      += f->size;
		skb->truesize += f->size;
		skb_shinfo(skb)->nr_frags++;
	}


	_skb = kzalloc(sizeof(*_skb), GFP_ATOMIC);
	if (!_skb) {
		kfree_skb(skb);
		return -ENOMEM;

	}

	_skb->priv   = priv;
	_skb->cookie = vsg->cookie;

	skb_shinfo(skb)->priv    = _skb;
	skb_shinfo(skb)->release = &venetdev_skb_release;

	atomic_inc(&priv->netif.rxq.outstanding);

	return 0;
}

static int
venetdev_sg_import_copy(struct venetdev *priv,
			struct venet_sg *vsg,
			struct sk_buff *skb)
{
	struct venet_sg_iterator iter;
	int ret;

	venet_sg_iter_init(&iter, vsg, priv->vbus.ctx);

	ret = venet_sg_iter_copy(&iter, skb->data, vsg->len);

	if (ret)
		kfree_skb(skb);

	return ret > 0 ? -EINVAL : ret;
}

/*
 * venetdev_sg_import - import an skb in scatter-gather mode
 *
 * assumes reference to priv->vbus.conn held
 */
static struct sk_buff *
venetdev_sg_import(struct venetdev *priv, void *ptr, int len)
{
	struct venet_sg *vsg;
	struct sk_buff *skb;
	size_t linear;
	int ret;
	bool zc = false;

	vsg = venetdev_sg_desc_get(priv, ptr, len);
	if (unlikely(!vsg)) {
		priv->netif.stats.rx_length_errors++;
		return NULL;
	}

	/*
	 * A packet is eligible for zero-copy handling if it both exceeds
	 * the zcthresh limit AND is of a GSO type packet.  When this state
	 * is detected, we only want to allocate just enough linear space
	 * for the header.  The rest we will load as paged data
	 */
	if (priv->vbus.ctx->ops->sg_map
	    && priv->vbus.evq.txc
	    && priv->zcthresh
	    && vsg->len >= priv->zcthresh
	    && vsg->flags & VENET_SG_FLAG_GSO) {
		zc = true;
		linear = vsg->gso.hdrlen;
	} else
		linear = vsg->len;

	skb = dev_alloc_skb(linear + NET_IP_ALIGN);
	if (unlikely(!skb)) {
		printk(KERN_INFO "VENETDEV: skb alloc failed:"	\
		       " memory squeeze.\n");
		priv->netif.stats.rx_dropped++;
		return NULL;
	}

	/* align IP on 16B boundary */
	skb_reserve(skb, NET_IP_ALIGN);
	skb_put(skb, linear);

	if (zc)
		ret = venetdev_sg_import_zc(priv, vsg, skb);
	else
		ret = venetdev_sg_import_copy(priv, vsg, skb);

	if (ret < 0) {
		kfree_skb(skb);
		return NULL;
	}

	if (vsg->flags & VENET_SG_FLAG_NEEDS_CSUM
	    && !skb_partial_csum_set(skb, vsg->csum.start, vsg->csum.offset)) {
		kfree_skb(skb);
		return NULL;
	}

	if (vsg->phdr.mac == ~0U || vsg->phdr.mac == 0)
		PDEBUG("mac header invalid!!!\n");

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, vsg->phdr.network);
	skb_set_transport_header(skb, vsg->phdr.transport);

	if (vsg->flags & VENET_SG_FLAG_GSO) {
		struct skb_shared_info *sinfo = skb_shinfo(skb);

		PDEBUG("GSO packet detected\n");

		switch (vsg->gso.type) {
		case VENET_GSO_TYPE_TCPV4:
			sinfo->gso_type = SKB_GSO_TCPV4;
			break;
		case VENET_GSO_TYPE_TCPV6:
			sinfo->gso_type = SKB_GSO_TCPV6;
			break;
		case VENET_GSO_TYPE_UDP:
			sinfo->gso_type = SKB_GSO_UDP;
			break;
		default:
			PDEBUG("Illegal GSO type: %d\n", vsg->gso.type);
			priv->netif.stats.rx_frame_errors++;
			kfree_skb(skb);
			return NULL;
		}

		if (vsg->flags & VENET_SG_FLAG_ECN)
			sinfo->gso_type |= SKB_GSO_TCP_ECN;

		sinfo->gso_size = vsg->gso.size;
		if (sinfo->gso_size == 0) {
			PDEBUG("Illegal GSO size: %d\n", vsg->gso.size);
			priv->netif.stats.rx_frame_errors++;
			kfree_skb(skb);
			return NULL;
		}

		/* Header must be checked, and gso_segs computed. */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;
	}

	return skb;
}

/*
 * ---------------------------
 * Flat (non Scatter-Gather) support
 * ---------------------------
 */

/*
 * venetdev_rx_flat - import an skb in non scatter-gather mode
 *
 * assumes reference to priv->vbus.conn held
 */
static struct sk_buff *
venetdev_flat_import(struct venetdev *priv, void *ptr, int len)
{
	struct vbus_memctx *ctx = priv->vbus.ctx;
	size_t maxlen = priv->netif.dev->mtu + ETH_HLEN;
	struct sk_buff *skb;
	int ret;

	if (len > maxlen) {
		priv->netif.stats.rx_length_errors++;
		return NULL;
	}

	skb = dev_alloc_skb(len + NET_IP_ALIGN);
	if (unlikely(!skb)) {
		printk(KERN_INFO "VENETDEV: skb alloc failed:"	\
		       " memory squeeze.\n");
		priv->netif.stats.rx_dropped++;
		return NULL;
	}

	/* align IP on 16B boundary */
	skb_reserve(skb, NET_IP_ALIGN);

	ret = ctx->ops->copy_from(ctx, skb_tail_pointer(skb), ptr, len);
	if (ret) {
		kfree_skb(skb);
		return NULL;
	}

	skb_put(skb, len);

	return skb;
}

static void
venetdev_skb_complete(struct _venetdev_skb *_skb)
{
	struct venetdev *priv = _skb->priv;
	unsigned long flags;
	bool signal = false;

	spin_lock_irqsave(&priv->lock, flags);

	if (atomic_dec_and_test(&priv->netif.rxq.outstanding))
		/*
		 * We reset the 'completed' count once we successfully drain
		 * the queue
		 */
		priv->netif.rxq.completed = 0;
	else
		priv->netif.rxq.completed++;

	if (waitqueue_active(&priv->netif.rxq.wq))
		wake_up(&priv->netif.rxq.wq);

	/*
	 * If txmitigation is disabled, or if we hit the txmitigation threshold,
	 * we need to send a signal to drain the evq
	 *
	 * We will also get a positive on txmitigation if this was the last
	 * packet since we reset 'completed' above.
	 */
	if (!priv->txmitigation
	    || !(priv->netif.rxq.completed % priv->txmitigation))
		signal = true;

	spin_unlock_irqrestore(&priv->lock, flags);

	if (signal)
		ioq_signal(priv->vbus.evq.queue.queue, 0);

	kfree(_skb);
}

static struct _venetdev_skb*
venetdev_dequeue_txclist(struct venetdev *priv)
{
	struct _venetdev_skb *skb;
	unsigned long flags;
	spin_lock_irqsave(&priv->vbus.evq.lock, flags);
	if (!list_empty(&priv->vbus.evq.txclist)) {
		skb = list_first_entry(&priv->vbus.evq.txclist,
					struct _venetdev_skb, list);
		list_del(&skb->list);
	} else {
		skb = NULL;
	}
	spin_unlock_irqrestore(&priv->vbus.evq.lock, flags);
	return skb;
}

static void
venetdev_queue_txclist(struct venetdev *priv, struct _venetdev_skb *skb)
{
	unsigned long flags;
	spin_lock_irqsave(&priv->vbus.evq.lock, flags);
	list_add_tail(&skb->list, &priv->vbus.evq.txclist);
	spin_unlock_irqrestore(&priv->vbus.evq.lock, flags);
}

static void
venetdev_txc_drain(struct venetdev *priv)
{
	struct _venetdev_skb *_skb;
	struct ioq *_ioq = priv->vbus.evq.queue.queue;

	while ((_skb = venetdev_dequeue_txclist(priv))) {
		if (evq_send_txc(priv, _skb->cookie)) {
			venetdev_queue_txclist(priv, _skb);
			ioq_notify_enable(_ioq, 0);
			return;
		}
		venetdev_skb_complete(_skb);
	}
	ioq_notify_disable(_ioq, 0);
}

static void
venetdev_txc_notifier(struct ioq_notifier *notifier)
{
	struct venetdev *priv;

	priv = container_of(notifier, struct venetdev, vbus.evq.queue.notifier);

	venetdev_txc_drain(priv);
}

static void
venetdev_skb_release(struct sk_buff *skb)
{
	struct _venetdev_skb *_skb
		= (struct _venetdev_skb *)skb_shinfo(skb)->priv;
	struct venetdev *priv = _skb->priv;

	venetdev_queue_txclist(priv, _skb);

	venetdev_txc_drain(priv);
}

/*
 * default out to netif_rx_ni.
 */

static int
venetdev_out(struct venetdev *priv, struct sk_buff *skb)
{
	/* Pass the buffer up to the stack */
	skb->dev      = priv->netif.dev;
	skb->protocol = eth_type_trans(skb, priv->netif.dev);

	return netif_rx_ni(skb);
}

/*
 * The poll implementation.
 */
static int
venetdev_rx(struct venetdev *priv)
{
	struct ioq                 *ioq;
	struct ioq                 *sioq;
	struct vbus_memctx         *ctx;
	int                         npackets = 0;
	int                         dirty = 0;
	struct ioq_iterator         iter;
	int                         ret;
	unsigned long               flags;
	struct vbus_connection     *conn;
	struct _venetdev_skb       *_skb;

	PDEBUG("polling...\n");

	spin_lock_irqsave(&priv->lock, flags);

	if (!priv->vbus.link) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return 0;
	}

	/*
	 * We take a reference to the connection object to ensure that the
	 * ioq/ctx references do not disappear out from under us.  We could
	 * acommplish the same thing more directly by acquiring a reference
	 * to the ioq and ctx explictly, but this would require an extra
	 * atomic_inc+dec pair, for no additional benefit
	 */
	conn = &priv->vbus.conn;
	vbus_connection_get(conn);

	ioq = priv->vbus.rxq.queue;
	if (priv->vbus.evq.txc)
		sioq = priv->vbus.evq.queue.queue;
	else
		sioq = priv->vbus.rxq.queue;

	ctx = priv->vbus.ctx;

	spin_unlock_irqrestore(&priv->lock, flags);

	/* We want to iterate on the head of the in-use index */
	ret = ioq_iter_init(ioq, &iter, ioq_idxtype_inuse, 0);
	BUG_ON(ret < 0);

	ret = ioq_iter_seek(&iter, ioq_seek_head, 0, 0);
	BUG_ON(ret < 0);

	/*
	 * The EOM is indicated by finding a packet that is still owned by
	 * the north side
	 */
	while (iter.desc->sown) {
		struct sk_buff *skb;
		bool txc = false;
		bool async = false;
		u64 cookie = 0;

		skb = priv->vbus.import(priv,
					(void *)iter.desc->ptr,
					iter.desc->len);
		if (unlikely(!skb)) {
			priv->netif.stats.rx_errors++;
			goto next;
		}

		if (priv->vbus.evq.txc) {
			if (skb_shinfo(skb)->release)
				async = true;
			else {
				/*
				 * If txc is enabled, and this packet does not
				 * have a deferred completion handler, it means
				 * we need to transmit a completion event on
				 * our own.
				 */
				if (priv->vbus.sg.enabled) {
					struct venet_sg *vsg;

					vsg = (struct venet_sg *)priv->vbus.sg.buf;
					cookie = vsg->cookie;
				} else
					cookie = iter.desc->cookie;

				txc = true;
			}
		}

		/* Maintain stats */
		npackets++;
		priv->netif.stats.rx_packets++;
		priv->netif.stats.rx_bytes += skb->len;

		priv->netif.out(priv, skb);
next:
		if (!async)
			dirty = 1;

		/* Advance the in-use head */
		ret = ioq_iter_pop(&iter, 0);
		BUG_ON(ret < 0);

		if (txc && evq_send_txc(priv, cookie)) {
			_skb = kzalloc(sizeof(*_skb), GFP_ATOMIC);
			if (!_skb) {
				printk(KERN_INFO "VENETDEV: " \
				"skb alloc failed: "	\
				"memory squeeze.\n");
				priv->netif.stats.tx_dropped++;
				kfree_skb(skb);
			} else {
				_skb->priv   = priv;
				_skb->cookie = cookie;

				skb_shinfo(skb)->priv    = _skb;
				venetdev_queue_txclist(priv, _skb);
				venetdev_txc_drain(priv);
			}
		}

		/* send up to N packets before sending tx-complete */
		if (dirty && (!priv->txmitigation
			      || !(npackets % priv->txmitigation))) {
			ioq_signal(sioq, 0);
			dirty = 0;
		}

	}

	PDEBUG("poll: %d packets received\n", npackets);

	if (dirty)
		ioq_signal(sioq, 0);

	/*
	 * If we processed all packets we're done, so reenable ints
	 */
	if (ioq_empty(ioq, ioq_idxtype_inuse)) {
		clear_bit(RX_SCHED, &priv->flags);
		ioq_notify_enable(ioq, 0);
		if (waitqueue_active(&priv->vbus.rx_empty))
			wake_up(&priv->vbus.rx_empty);
	}

	vbus_connection_put(conn);

	return 0;
}

static int venetdev_rx_thread(void *__priv)
{
	struct venetdev *priv = __priv;
	struct vbus_memctx *ctx = priv->vbus.ctx;
	struct mm_struct *mm = NULL;

	if (ctx->ops->mm_get) {
		mm = ctx->ops->mm_get(ctx);
		BUG_ON(!mm);

		use_mm(mm);
	}

	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (!freezing(current) &&
		    !kthread_should_stop() &&
		    !test_bit(RX_SCHED, &priv->flags))
			schedule();
		set_current_state(TASK_RUNNING);

		try_to_freeze();

		if (kthread_should_stop())
			break;

		venetdev_rx(priv);
	}

	if (mm) {
		unuse_mm(mm);
		mmput(mm);
	}

	return 0;
}

/* assumes priv->lock is held */
static void
venetdev_check_netif_congestion(struct venetdev *priv)
{
	struct ioq *ioq = priv->vbus.txq.queue;

	if (priv->vbus.link
	    && priv->netif.txq.len < ioq_remain(ioq, ioq_idxtype_inuse)
	    && test_and_clear_bit(TX_NETIF_CONGESTED, &priv->flags)) {
		PDEBUG("NETIF congestion cleared\n");
		venetdev_txq_notify_dec(priv);

		if (priv->netif.link)
			netif_wake_queue(priv->netif.dev);
	}
}

/*
 *-----------------------------------------------------------
 * tx logic
 *-----------------------------------------------------------
 */

struct venet_txstream {
	struct venetdev       *priv;
	struct ioq_ring_desc  *desc;
	int (*write)(struct venet_txstream *str, const void *src,
		     unsigned long len);
};

/* flat_txstream: handles linear descriptors */
struct venet_flat_txstream {
	void                  *dst;
	struct venet_txstream  txstream;
};

static struct venet_flat_txstream *
to_flat_txstream(struct venet_txstream *txstream)
{
	return container_of(txstream, struct venet_flat_txstream, txstream);
}

static int
flat_txstream_write(struct venet_txstream *str, const void *src,
		    unsigned long len)
{
	struct venet_flat_txstream *_str = to_flat_txstream(str);
	struct vbus_memctx *ctx = str->priv->vbus.ctx;
	int bytes;
	int ret;

	PDEBUG("copy %d bytes: %p to %p\n",
	       len, src, _str->dst);

	ret = ctx->ops->copy_to(ctx, _str->dst, src, len);
	if (ret < 0)
		return ret;

	bytes = len - ret;

	_str->dst += bytes;
	str->desc->len += bytes;

	PDEBUG("%d bytes remain\n", ret);

	return ret;
}

/* sg_txstream: handles non-linear descriptors */
struct venet_sg_txstream {
	struct venet_sg       *vsg;
	void                  *dst;
	size_t                 remain;
	int                    index;
	struct venet_txstream  txstream;
};

static struct venet_sg_txstream *
to_sg_txstream(struct venet_txstream *txstream)
{
	return container_of(txstream, struct venet_sg_txstream, txstream);
}

/*
 * We ran out of space, so we need to grab another
 * buffer from the page-queue and tack it on the end
 */
static void
sg_txstream_replenish(struct venet_sg_txstream *_str)
{
	struct venetdev    *priv = _str->txstream.priv;
	struct venet_sg    *vsg = _str->vsg;
	struct venet_iov   *iov = &vsg->iov[++_str->index];
	struct ioq         *ioq = priv->vbus.l4ro.pageq.queue;
	struct ioq_iterator iter;
	int                 ret;

	PDEBUG("replenish stream\n");

	ret = ioq_iter_init(ioq, &iter, ioq_idxtype_inuse, 0);
	BUG_ON(ret < 0);

	ret = ioq_iter_seek(&iter, ioq_seek_head, 0, 0);
	BUG_ON(ret < 0);

	if (!iter.desc->sown) {
		/* There are no more pages available, so we will wait */
		ioq_notify_enable(ioq, 0);
		wait_event(ioq->wq, iter.desc->sown);
		ioq_notify_disable(ioq, 0);
	}

	_str->dst    = (void *)iter.desc->ptr;
	_str->remain = iter.desc->len;
	iov->ptr     = iter.desc->cookie;
	iov->len     = 0;
	vsg->count++;

	ret = ioq_iter_pop(&iter, 0);
	BUG_ON(ret < 0);
}

static int
sg_txstream_write(struct venet_txstream *str, const void *src, unsigned long len)
{
	struct venet_sg_txstream *_str = to_sg_txstream(str);
	struct vbus_memctx       *ctx  = str->priv->vbus.ctx;
	struct venet_sg          *vsg  = _str->vsg;
	int                       ret;

	while (len) {
		struct venet_iov *iov         = &vsg->iov[_str->index];
		int               bytestocopy = min_t(size_t, len, _str->remain);

		if (!bytestocopy) {
			sg_txstream_replenish(_str);
			continue;
		}

		PDEBUG("copy %d bytes: %p to %p\n",
		       bytestocopy, src, _str->dst);

		ret = ctx->ops->copy_to(ctx, _str->dst, src, bytestocopy);
		if (ret)
			break;

		_str->dst    += bytestocopy;
		_str->remain -= bytestocopy;
		src          += bytestocopy;
		len          -= bytestocopy;
		vsg->len     += bytestocopy;
		iov->len     += bytestocopy;
	}

	PDEBUG("complete with %d bytes remain\n", len);

	return len;
}

/* handles streaming fragmented packets */
static int
skb_nonlinear_stream(struct venet_txstream *str, struct sk_buff *skb)
{
	struct scatterlist sgl[MAX_SKB_FRAGS+1];
	struct scatterlist *sg;
	int count, maxcount = ARRAY_SIZE(sgl);
	int bytes = 0;
	int i;
	int ret;

	sg_init_table(sgl, maxcount);

	count = skb_to_sgvec(skb, sgl, 0, skb->len);
	BUG_ON(count > maxcount);

	/* linearize the payload directly into the stream */
	for_each_sg(sgl, sg, count, i) {
		size_t len = sg->length;
		void *src  = sg_virt(sg);

		ret = str->write(str, src, len);
		if (ret)
			break;

		bytes += len;
	}

	return skb->len - bytes;
}

static int
skb_to_txstream(struct venet_txstream *str, struct sk_buff *skb)
{
	int ret;

	if (!skb_shinfo(skb)->nr_frags) {
		PDEBUG("linear SKB detected\n");
		ret = str->write(str, skb->data, skb->len);
	} else {
		PDEBUG("non-linear SKB detected\n");
		ret = skb_nonlinear_stream(str, skb);
	}

	return ret;
}

static int
venetdev_flat_export(struct venetdev *priv,
		     struct ioq_ring_desc *desc,
		     struct sk_buff *skb)
{
	struct venet_flat_txstream _str = {
		.dst = (void *)desc->ptr,
		.txstream = {
			.priv = priv,
			.desc = desc,
			.write = &flat_txstream_write,
		},
	};

	if (skb->len > desc->len)
		return skb->len;

	desc->len = 0;

	return skb_to_txstream(&_str.txstream, skb);
}

static int
venetdev_sg_export(struct venetdev *priv,
		   struct ioq_ring_desc *desc,
		   struct sk_buff *skb)
{
	void *_vsg = priv->vbus.l4ro.shm->ptr + (size_t)desc->ptr;
	struct venet_sg *vsg = (struct venet_sg *)_vsg;
	struct venet_iov *iov = &vsg->iov[0];
	struct venet_sg_txstream _str = {
		.vsg = vsg,
		.dst = (void *)iov->ptr,
		.remain = iov->len,
		.index = 0,
		.txstream = {
			.priv = priv,
			.desc = desc,
			.write = &sg_txstream_write,
		},
	};

	PDEBUG("sg-export: %d bytes\n", skb->len);

	if (!skb_is_gso(skb) && skb->len > iov->len) {
		PDEBUG("skb is larger than mtu: %d/%d\n", skb->len, iov->len);
		return skb->len;
	}

	vsg->len   = 0;
	vsg->count = 1;
	iov->len   = 0;

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		PDEBUG("needs csum\n");
		vsg->flags      |= VENET_SG_FLAG_NEEDS_CSUM;
		vsg->csum.start  = skb->csum_start - skb_headroom(skb);
		vsg->csum.offset = skb->csum_offset;
	}

	if (skb_is_gso(skb)) {
		struct skb_shared_info *sinfo = skb_shinfo(skb);

		PDEBUG("L4RO frame\n");

		vsg->flags |= VENET_SG_FLAG_GSO;

		vsg->gso.hdrlen = skb_headlen(skb);
		vsg->gso.size = sinfo->gso_size;
		if (sinfo->gso_type & SKB_GSO_TCPV4)
			vsg->gso.type = VENET_GSO_TYPE_TCPV4;
		else if (sinfo->gso_type & SKB_GSO_TCPV6)
			vsg->gso.type = VENET_GSO_TYPE_TCPV6;
		else if (sinfo->gso_type & SKB_GSO_UDP)
			vsg->gso.type = VENET_GSO_TYPE_UDP;
		else
			panic("Virtual-Ethernet: unknown GSO type "	\
			      "0x%x\n", sinfo->gso_type);

		if (sinfo->gso_type & SKB_GSO_TCP_ECN)
			vsg->flags |= VENET_SG_FLAG_ECN;
	}

	return skb_to_txstream(&_str.txstream, skb);
}

static int
venetdev_tx(struct venetdev *priv)
{
	struct sk_buff             *skb;
	struct ioq_iterator         iter;
	struct ioq                 *ioq = NULL;
	struct vbus_memctx         *ctx;
	int                         ret;
	int                         npackets = 0;
	unsigned long               flags;
	struct vbus_connection     *conn;

	PDEBUG("tx-thread\n");

	spin_lock_irqsave(&priv->lock, flags);

	if (unlikely(!priv->vbus.link)) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return 0;
	}

	/*
	 * We take a reference to the connection object to ensure that the
	 * ioq/ctx references do not disappear out from under us.  We could
	 * acommplish the same thing more directly by acquiring a reference
	 * to the ioq and ctx explictly, but this would require an extra
	 * atomic_inc+dec pair, for no additional benefit
	 */
	conn = &priv->vbus.conn;
	vbus_connection_get(conn);

	ioq = priv->vbus.txq.queue;
	ctx = priv->vbus.ctx;

	ret = ioq_iter_init(ioq, &iter, ioq_idxtype_inuse, IOQ_ITER_AUTOUPDATE);
	BUG_ON(ret < 0);

	ret = ioq_iter_seek(&iter, ioq_seek_tail, 0, 0);
	BUG_ON(ret < 0);

	while (priv->vbus.link && iter.desc->sown && priv->netif.txq.len) {

		skb = __skb_dequeue(&priv->netif.txq.list);
		if (!skb)
			break;

		spin_unlock_irqrestore(&priv->lock, flags);

		PDEBUG("tx-thread: sending %d bytes\n", skb->len);

		ret = priv->vbus.export(priv, iter.desc, skb);
		if (!ret) {
			npackets++;
			priv->netif.stats.tx_packets++;
			priv->netif.stats.tx_bytes += skb->len;

			ret = ioq_iter_push(&iter, 0);
			BUG_ON(ret < 0);
		} else
			priv->netif.stats.tx_errors++;

		dev_kfree_skb(skb);
		priv->netif.dev->trans_start = jiffies; /* save the timestamp */

		spin_lock_irqsave(&priv->lock, flags);

		priv->netif.txq.len--;
	}

	PDEBUG("send complete\n");

	if (!priv->vbus.link || !priv->netif.txq.len) {
		PDEBUG("descheduling TX: link=%d, len=%d\n",
		       priv->vbus.link, priv->netif.txq.len);
		clear_bit(TX_SCHED, &priv->flags);
	} else if (!test_and_set_bit(TX_IOQ_CONGESTED, &priv->flags)) {
		PDEBUG("congested with %d packets still queued\n",
		       priv->netif.txq.len);
		venetdev_txq_notify_inc(priv);
	}

	venetdev_check_netif_congestion(priv);

	spin_unlock_irqrestore(&priv->lock, flags);

	vbus_connection_put(conn);

	return npackets;
}

static int venetdev_tx_thread(void *__priv)
{
	struct venetdev *priv = __priv;
	struct vbus_memctx *ctx = priv->vbus.ctx;
	struct mm_struct *mm = NULL;

	if (ctx->ops->mm_get) {
		mm = ctx->ops->mm_get(ctx);
		BUG_ON(!mm);

		use_mm(mm);
	}

	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (!freezing(current) &&
		    !kthread_should_stop() &&
		    (test_bit(TX_IOQ_CONGESTED, &priv->flags) ||
		     !test_bit(TX_SCHED, &priv->flags)))
			schedule();
		set_current_state(TASK_RUNNING);

		PDEBUG("tx wakeup: %s%s%s\n",
		       test_bit(TX_SCHED, &priv->flags) ? "s" : "-",
		       test_bit(TX_IOQ_CONGESTED, &priv->flags) ? "c" : "-",
		       test_bit(TX_NETIF_CONGESTED, &priv->flags) ? "b" : "-"
			);

		try_to_freeze();

		if (kthread_should_stop())
			break;

		venetdev_tx(priv);
	}

	if (mm) {
		unuse_mm(mm);
		mmput(mm);
	}

	return 0;
}

static void
venetdev_deferred_tx(struct venetdev *priv)
{
	PDEBUG("wake up txthread\n");
	wake_up_process(priv->txthread);
}

/* assumes priv->lock is held */
static void
venetdev_apply_backpressure(struct venetdev *priv)
{
	PDEBUG("backpressure\n");

	if (!test_and_set_bit(TX_NETIF_CONGESTED, &priv->flags)) {
		/*
		 * We must flow-control the kernel by disabling the queue
		 */
		netif_stop_queue(priv->netif.dev);
		venetdev_txq_notify_inc(priv);
	}
}

/*
 * Transmit a packet (called by the kernel)
 *
 * We want to perform ctx->copy_to() operations from a sleepable process
 * context, so we defer the actual tx operations to a thread.
 * However, we want to be careful that we do not double-buffer the
 * queue, so we create a buffer whose space dynamically grows and
 * shrinks with the availability of the actual IOQ.  This means that
 * the netif flow control is still managed by the actual consumer,
 * thereby avoiding the creation of an extra servo-loop to the equation.
 */

int
venetdev_xmit(struct sk_buff *skb, struct venetdev *priv)
{
	struct ioq      *ioq = NULL;
	unsigned long    flags;

	PDEBUG("queuing %d bytes\n", skb->len);

	spin_lock_irqsave(&priv->lock, flags);

	ioq = priv->vbus.txq.queue;

	BUG_ON(test_bit(TX_NETIF_CONGESTED, &priv->flags));

	if (!priv->vbus.link) {
		/*
		 * We have a link-down condition
		 */
		printk(KERN_ERR "VENETDEV: tx on link down\n");
		goto flowcontrol;
	}

	__skb_queue_tail(&priv->netif.txq.list, skb);
	priv->netif.txq.len++;
	set_bit(TX_SCHED, &priv->flags);

	if (priv->netif.txq.len >= ioq_remain(ioq, ioq_idxtype_inuse))
		venetdev_apply_backpressure(priv);

	spin_unlock_irqrestore(&priv->lock, flags);

	venetdev_deferred_tx(priv);

	return NETDEV_TX_OK;

flowcontrol:
	venetdev_apply_backpressure(priv);

	spin_unlock_irqrestore(&priv->lock, flags);

	return NETDEV_TX_BUSY;
}

int
venetdev_netdev_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct venetdev *priv = netdev_priv(dev);

	return venetdev_xmit(skb, priv);
}


/*
 * Ioctl commands
 */
int
venetdev_netdev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	PDEBUG("ioctl\n");
	return 0;
}

/*
 * Return statistics to the caller
 */
struct net_device_stats *
venetdev_get_stats(struct venetdev *priv)
{
	return &priv->netif.stats;
}

struct net_device_stats *
venetdev_netdev_stats(struct net_device *dev)
{
	struct venetdev *priv = netdev_priv(dev);
	return venetdev_get_stats(priv);
}

/*
 * receive interrupt-service-routine - called whenever the vbus-driver signals
 * our IOQ to indicate more inbound packets are ready.
 */
static void
venetdev_rx_isr(struct ioq_notifier *notifier)
{
	struct venetdev *priv;
	unsigned long flags;
	ktime_t now;
	int direct = 0;

	priv = container_of(notifier, struct venetdev, vbus.rxq.notifier);

	spin_lock_irqsave(&priv->lock, flags);

	now = ktime_get();

	if (priv->vbus.link && priv->netif.link
	    && !ioq_empty(priv->vbus.rxq.queue, ioq_idxtype_inuse)
	    && !test_and_set_bit(RX_SCHED, &priv->flags)) {
		s64 delta = 0;

		ioq_notify_disable(priv->vbus.rxq.queue, 0);
		barrier();

		if (priv->burst.thresh) {
			delta = ktime_us_delta(now, priv->burst.expires);
			priv->burst.expires = ktime_add_us(now,
							   priv->burst.thresh);
		}

		if (delta <= 0)
			/*
			 * Back to back calls (within our burst threshold)
			 * mean we are bursting and will therefore schedule
			 * our RX thread to handle the work in parallel
			 * for maximum throughput.
			 */
			wake_up_process(priv->rxthread);
		else
			/*
			 * Otherwise we will blast these packets directly
			 * in our context as a latency optimization
			 */
			direct = 1;
	}


	spin_unlock_irqrestore(&priv->lock, flags);

	if (direct)
		venetdev_rx(priv);
}

/*
 * transmit interrupt-service-routine - called whenever the vbus-driver signals
 * our IOQ to indicate there is more room in the TX queue
 */
static void
venetdev_tx_isr(struct ioq_notifier *notifier)
{
	struct venetdev *priv;
	unsigned long flags;

	priv = container_of(notifier, struct venetdev, vbus.txq.notifier);

	spin_lock_irqsave(&priv->lock, flags);

	if (priv->vbus.link
	    && !ioq_full(priv->vbus.txq.queue, ioq_idxtype_inuse)
	    && test_and_clear_bit(TX_IOQ_CONGESTED, &priv->flags)) {
		PDEBUG("IOQ congestion cleared\n");
		venetdev_txq_notify_dec(priv);

		if (priv->netif.link)
			wake_up_process(priv->txthread);
	}

	venetdev_check_netif_congestion(priv);

	spin_unlock_irqrestore(&priv->lock, flags);
}

static int
venetdev_vlink_up(struct venetdev *priv)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);

	if (priv->vbus.link) {
		ret = -EEXIST;
		goto out;
	}

	if (!priv->vbus.rxq.queue || !priv->vbus.txq.queue) {
		ret = -EINVAL;
		goto out;
	}

	priv->vbus.link = 1;

	if (priv->netif.link)
		netif_carrier_on(priv->netif.dev);

	venetdev_check_netif_congestion(priv);

	/* FIXME: we always assume the link is up for now */
	evq_send_linkstatus(priv, true);

	ioq_notify_enable(priv->vbus.rxq.queue, 0);

out:
	spin_unlock_irqrestore(&priv->lock, flags);
	return ret;
}

/* Assumes priv->lock held */
int
_venetdev_vlink_down(struct venetdev *priv)
{
	struct sk_buff *skb;

	if (!priv->vbus.link)
		return -ENOENT;

	priv->vbus.link = 0;

	if (priv->netif.link)
		netif_carrier_off(priv->netif.dev);

	/* just trash whatever might have been pending */
	while ((skb = __skb_dequeue(&priv->netif.txq.list)))
		dev_kfree_skb(skb);

	priv->netif.txq.len = 0;

	/* And deschedule any pending processing */
	clear_bit(RX_SCHED, &priv->flags);
	clear_bit(TX_SCHED, &priv->flags);

	ioq_notify_disable(priv->vbus.rxq.queue, 0);

	return 0;
}

static int
venetdev_vlink_down(struct venetdev *priv)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&priv->lock, flags);
	ret = _venetdev_vlink_down(priv);
	spin_unlock_irqrestore(&priv->lock, flags);

	return ret;
}

static int
venetdev_macquery(struct venetdev *priv, void *data, unsigned long len)
{
	struct vbus_memctx *ctx = priv->vbus.ctx;
	int ret;

	if (len != ETH_ALEN)
		return -EINVAL;

	ret = ctx->ops->copy_to(ctx, data, priv->cmac, ETH_ALEN);
	if (ret)
		return -EFAULT;

	return 0;
}

static u32
venetdev_negcap_sg(struct venetdev *priv, u32 requested)
{
	u32 available = VENET_CAP_SG|VENET_CAP_TSO4|VENET_CAP_TSO6
		|VENET_CAP_ECN|VENET_CAP_PMTD;
	u32 ret;

	ret = available & requested;

	if (ret & VENET_CAP_SG) {
		priv->vbus.sg.enabled = true;
		priv->vbus.import = &venetdev_sg_import;
	}

	if (ret & VENET_CAP_PMTD)
		priv->vbus.pmtd.enabled = true;

	return ret;
}

static u32
venetdev_negcap_evq(struct venetdev *priv, u32 requested)
{
	u32 available = VENET_CAP_EVQ_LINKSTATE|VENET_CAP_EVQ_TXC;
	u32 ret;

	ret = available & requested;

	if (ret) {
		priv->vbus.evq.enabled = true;

		if (ret & VENET_CAP_EVQ_LINKSTATE)
			priv->vbus.evq.linkstate = true;
		if (ret & VENET_CAP_EVQ_TXC)
			priv->vbus.evq.txc = true;
	}

	return ret;
}

static u32
venetdev_negcap_l4ro(struct venetdev *priv, u32 requested)
{
	u32 available = VENET_CAP_SG|VENET_CAP_TSO4|VENET_CAP_TSO6
		|VENET_CAP_ECN;
	u32 ret;

	ret = available & requested;

	if (ret & VENET_CAP_SG) {
		struct net_device *dev = priv->netif.dev;

		priv->vbus.l4ro.available = true;
		priv->vbus.export = &venetdev_sg_export;

		dev->features |= NETIF_F_SG|NETIF_F_HW_CSUM|NETIF_F_FRAGLIST;

		if (ret & VENET_CAP_TSO4)
			dev->features |= NETIF_F_TSO;
		if (ret & VENET_CAP_UFO)
			dev->features |= NETIF_F_UFO;
		if (ret & VENET_CAP_TSO6)
			dev->features |= NETIF_F_TSO6;
		if (ret & VENET_CAP_ECN)
			dev->features |= NETIF_F_TSO_ECN;
	}

	return ret;
}

/*
 * Negotiate Capabilities - This function is provided so that the
 * interface may be extended without breaking ABI compatability
 *
 * The caller is expected to send down any capabilities they would like
 * to enable, and the device will OR them with capabilities that it
 * supports.  This value is then returned so that both sides may
 * ascertain the lowest-common-denominator of features to enable
 */
static int
venetdev_negcap(struct venetdev *priv, void *data, unsigned long len)
{
	struct vbus_memctx *ctx = priv->vbus.ctx;
	struct venet_capabilities caps;
	int ret;

	if (len != sizeof(caps))
		return -EINVAL;

	if (priv->vbus.link)
		return -EINVAL;

	ret = ctx->ops->copy_from(ctx, &caps, data, sizeof(caps));
	if (ret)
		return -EFAULT;

	switch (caps.gid) {
	case VENET_CAP_GROUP_SG:
		caps.bits = venetdev_negcap_sg(priv, caps.bits);
		break;
	case VENET_CAP_GROUP_EVENTQ:
		caps.bits = venetdev_negcap_evq(priv, caps.bits);
		break;
	case VENET_CAP_GROUP_L4RO:
		caps.bits = venetdev_negcap_l4ro(priv, caps.bits);
		break;
	default:
		caps.bits = 0;
		break;
	}

	ret = ctx->ops->copy_to(ctx, data, &caps, sizeof(caps));
	if (ret)
		return -EFAULT;

	return 0;
}

/*
 * Walk through and flush each remaining descriptor by returning
 * a zero length packet.
 *
 * This is useful, for instance, when the driver is changing the MTU
 * and wants to reclaim all the existing buffers outstanding which
 * are a different size than the new MTU
 */
static int
venetdev_flushrx(struct venetdev *priv)
{
	struct ioq_iterator         iter;
	struct ioq                 *ioq = NULL;
	int                         ret;
	unsigned long               flags;

	PDEBUG("flushrx\n");

	spin_lock_irqsave(&priv->lock, flags);

	if (unlikely(!priv->vbus.link)) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return -EINVAL;
	}

	ioq = priv->vbus.txq.queue;

	ret = ioq_iter_init(ioq, &iter, ioq_idxtype_inuse, 0);
	BUG_ON(ret < 0);

	ret = ioq_iter_seek(&iter, ioq_seek_tail, 0, 0);
	BUG_ON(ret < 0);

	while (iter.desc->sown) {
		iter.desc->len = 0;
		ret = ioq_iter_push(&iter, 0);
		if (ret < 0)
			SHM_SIGNAL_FAULT(ioq->signal, "could not flushrx");
	}

	PDEBUG("flushrx complete\n");

	if (!test_and_set_bit(TX_IOQ_CONGESTED, &priv->flags)) {
		PDEBUG("congested with %d packets still queued\n",
		       priv->netif.txq.len);
		venetdev_txq_notify_inc(priv);
	}

	/*
	 * we purposely do not ioq_signal() the other side here.  Since
	 * this function was invoked by the client, they can take care
	 * of explcitly calling any reclaim code if they like.  This also
	 * avoids a potential deadlock in case turning around and injecting
	 * a signal while we are in a call() is problematic to the
	 * connector design
	 */

	venetdev_check_netif_congestion(priv);

	spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

void venetdev_common_init(struct venetdev *device)
{
	INIT_LIST_HEAD(&device->vbus.evq.txclist);
	device->vbus.import      = &venetdev_flat_import;
	device->vbus.export      = &venetdev_flat_export;
	init_waitqueue_head(&device->vbus.rx_empty);
	device->burst.thresh     = 0; /* microseconds, 0 = disabled */
	device->txmitigation     = 10; /* nr-packets, 0 = disabled */
	device->zcthresh         = 512; /* bytes */

	/*
	 * netif init
	 */
	skb_queue_head_init(&device->netif.txq.list);
	device->netif.txq.len = 0;

	atomic_set(&device->netif.rxq.outstanding, 0);
	device->netif.rxq.completed = 0;
	init_waitqueue_head(&device->netif.rxq.wq);

	device->netif.out = venetdev_out;
}

void venetdev_dev_init(struct venetdev *device, struct net_device *dev)
{
	device->netif.dev = dev;

	ether_setup(dev); /* assign some of the fields */

	memcpy(dev->dev_addr, device->hmac, ETH_ALEN);

	dev->features |= NETIF_F_HIGHDMA;

}

static int
venetdev_evqquery(struct venetdev *priv, void *data, unsigned long len)
{
	struct vbus_memctx *ctx = priv->vbus.ctx;
	struct venet_eventq_query query;
	int ret;

	if (len != sizeof(query))
		return -EINVAL;

	if (priv->vbus.link)
		return -EINVAL;

	ret = ctx->ops->copy_from(ctx, &query, data, sizeof(query));
	if (ret)
		return -EFAULT;

	if (query.flags)
		return -EINVAL;

	query.evsize = EVQ_EVSIZE;
	query.dpid   = EVQ_DPOOL_ID;
	query.qid    = EVQ_QUEUE_ID;

	ret = ctx->ops->copy_to(ctx, data, &query, sizeof(query));
	if (ret)
		return -EFAULT;

	return 0;
}

static int
venetdev_l4roquery(struct venetdev *priv, void *data, unsigned long len)
{
	struct vbus_memctx *ctx = priv->vbus.ctx;
	struct venet_l4ro_query query;
	int ret;

	if (len != sizeof(query))
		return -EINVAL;

	if (priv->vbus.link)
		return -EINVAL;

	ret = ctx->ops->copy_from(ctx, &query, data, sizeof(query));
	if (ret)
		return -EFAULT;

	if (query.flags)
		return -EINVAL;

	query.dpid   = L4RO_DPOOL_ID;
	query.pqid   = L4RO_PAGEQ_ID;

	ret = ctx->ops->copy_to(ctx, data, &query, sizeof(query));
	if (ret)
		return -EFAULT;

	return 0;
}

/*
 * This is called whenever a driver wants to perform a synchronous
 * "function call" to our device.  It is similar to the notion of
 * an ioctl().  The parameters are part of the ABI between the device
 * and driver.
 */
int
venetdev_vlink_call(struct vbus_connection *conn,
		    unsigned long func,
		    void *data,
		    unsigned long len,
		    unsigned long flags)
{
	struct venetdev *priv = conn_to_priv(conn);

	PDEBUG("call -> %d with %p/%d\n", func, data, len);

	switch (func) {
	case VENET_FUNC_LINKUP:
		return venetdev_vlink_up(priv);
	case VENET_FUNC_LINKDOWN:
		return venetdev_vlink_down(priv);
	case VENET_FUNC_MACQUERY:
		return venetdev_macquery(priv, data, len);
	case VENET_FUNC_NEGCAP:
		return venetdev_negcap(priv, data, len);
	case VENET_FUNC_FLUSHRX:
		return venetdev_flushrx(priv);
	case VENET_FUNC_PMTDQUERY:
		return PMTD_POOL_ID;
	case VENET_FUNC_EVQQUERY:
		return venetdev_evqquery(priv, data, len);
	case VENET_FUNC_L4ROQUERY:
		return venetdev_l4roquery(priv, data, len);
	default:
		return -EINVAL;
	}
}

/*
 * This is called whenever a driver wants to open a new IOQ between itself
 * and our device.  The "id" field is meant to convey meaning to the device
 * as to what the intended use of this IOQ is.  For instance, for venet "id=0"
 * means "rx" and "id=1" = "tx".  That namespace is managed by the device
 * and should be understood by the driver as part of its ABI agreement.
 *
 * The device should take a reference to the IOQ via ioq_get() and hold it
 * until the connection is released.
 */
int
venetdev_vlink_shm(struct vbus_connection *conn,
		   unsigned long id,
		   struct vbus_shm *shm,
		   struct shm_signal *signal,
		   unsigned long flags)
{
	struct venetdev *priv = conn_to_priv(conn);

	PDEBUG("queue -> %p/%d attached\n", shm, id);

	switch (id) {
	case VENET_QUEUE_RX:
		return venetdev_queue_init(&priv->vbus.txq, shm, signal,
					   venetdev_tx_isr);
	case VENET_QUEUE_TX:
		return venetdev_queue_init(&priv->vbus.rxq, shm, signal,
					   venetdev_rx_isr);
	case PMTD_POOL_ID:
		return venetdev_pmtd_init(priv, shm, signal);
	case EVQ_DPOOL_ID:
		return venetdev_evq_dpool_init(priv, shm, signal);
	case EVQ_QUEUE_ID:
		return venetdev_evq_queue_init(priv, shm, signal,
					       venetdev_txc_notifier);
	case L4RO_DPOOL_ID:
		return venetdev_l4ro_dpool_init(priv, shm, signal);
	case L4RO_PAGEQ_ID:
		return venetdev_queue_init(&priv->vbus.l4ro.pageq, shm, signal,
					   NULL);
	default:
		return -EINVAL;
	}

	return 0;
}

void
venetdev_vlink_close(struct vbus_connection *conn)
{
	struct venetdev *priv = conn_to_priv(conn);
	unsigned long flags;

	PDEBUG("connection closed\n");

	/* Block until all posted packets have been processed */
	wait_event(priv->vbus.rx_empty, (!test_bit(RX_SCHED, &priv->flags)));
	wait_event(priv->netif.rxq.wq,
		   (!atomic_read(&priv->netif.rxq.outstanding)));

	spin_lock_irqsave(&priv->lock, flags);

	priv->vbus.opened = false;
	_venetdev_vlink_down(priv);

	spin_unlock_irqrestore(&priv->lock, flags);
}

/*
 * This is called whenever the driver closes all references to our device
 */
void
venetdev_vlink_release(struct vbus_connection *conn)
{
	struct venetdev *priv = conn_to_priv(conn);

	PDEBUG("connection released\n");

	venetdev_queue_release(&priv->vbus.rxq);
	venetdev_queue_release(&priv->vbus.txq);
	vbus_memctx_put(priv->vbus.ctx);

	kobject_put(priv->vbus.dev.kobj);

	priv->vbus.sg.enabled = false;
	priv->vbus.import = &venetdev_flat_import;
	priv->vbus.export = &venetdev_flat_export;
	priv->vbus.sg.len = 0;

	if (priv->vbus.pmtd.shm)
		vbus_shm_put(priv->vbus.pmtd.shm);
	priv->vbus.pmtd.shm = NULL;
	priv->vbus.pmtd.enabled = false;

	if (priv->vbus.evq.shm)
		vbus_shm_put(priv->vbus.evq.shm);
	if (priv->vbus.evq.queue.queue)
		venetdev_queue_release(&priv->vbus.evq.queue);
	priv->vbus.evq.shm = NULL;
	priv->vbus.evq.enabled = false;
	priv->vbus.evq.linkstate = false;
	priv->vbus.evq.txc = false;

	if (priv->vbus.l4ro.shm)
		vbus_shm_put(priv->vbus.l4ro.shm);
	if (priv->vbus.l4ro.pageq.queue)
		venetdev_queue_release(&priv->vbus.l4ro.pageq);
	priv->vbus.l4ro.shm = NULL;
	priv->vbus.l4ro.available = false;
	priv->vbus.l4ro.enabled = false;
}

/*
 * Interface attributes show up as files under
 * /sys/vbus/devices/$devid
 */
static ssize_t
host_mac_show(struct vbus_device *dev, struct vbus_device_attribute *attr,
	 char *buf)
{
	struct venetdev *priv = vdev_to_priv(dev);

	return sysfs_format_mac(buf, priv->hmac, ETH_ALEN);
}

struct vbus_device_attribute attr_hmac =
	__ATTR_RO(host_mac);

ssize_t
cmac_store(struct vbus_device *dev, struct vbus_device_attribute *attr,
	      const char *buf, size_t count)
{
	struct venetdev *priv = vdev_to_priv(dev);
	const char *pbuf = buf;
	unsigned int uc;
	int i;

	/*
	 * Format 00:11:22:33:44:55
	 */
	if (count != 18)
		return -EINVAL;

	for (i = 2; i < 17; i += 3) {
		if (pbuf[i] != ':')
			return -EINVAL;
	}

	if (priv->vbus.opened)
		return -EINVAL;

	for (i = 0; i < ETH_ALEN; i++) {
		sscanf(pbuf, "%x", &uc);
		pbuf = pbuf + 3;
		priv->cmac[i] = (u8)uc;
	}

	return count;
}

ssize_t
client_mac_show(struct vbus_device *dev, struct vbus_device_attribute *attr,
	 char *buf)
{
	struct venetdev *priv = vdev_to_priv(dev);

	return sysfs_format_mac(buf, priv->cmac, ETH_ALEN);
}

struct vbus_device_attribute attr_cmac =
	__ATTR(client_mac, S_IRUGO | S_IWUSR, client_mac_show, cmac_store);

ssize_t
enabled_show(struct vbus_device *dev, struct vbus_device_attribute *attr,
	 char *buf)
{
	struct venetdev *priv = vdev_to_priv(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", priv->netif.enabled);
}

ssize_t
enabled_store(struct vbus_device *dev, struct vbus_device_attribute *attr,
	      const char *buf, size_t count)
{
	struct venetdev *priv = vdev_to_priv(dev);
	int enabled = -1;
	int ret = 0;

	if (count > 0)
		sscanf(buf, "%d", &enabled);

	if (enabled != 0 && enabled != 1)
		return -EINVAL;

	if (enabled && !priv->netif.enabled) {
		/* need to un-initialize certain fields of the
		   net_device so that it may be re-registered */
		priv->netif.dev->reg_state = NETREG_UNINITIALIZED;
		priv->netif.dev->dev.kobj.state_initialized = 0;
		ret = register_netdev(priv->netif.dev);
	}

	if (!enabled && priv->netif.enabled)
		venetdev_netdev_unregister(priv);

	if (ret < 0)
		return ret;

	priv->netif.enabled = enabled;

	return count;
}

struct vbus_device_attribute attr_enabled =
	__ATTR(enabled, S_IRUGO | S_IWUSR, enabled_show, enabled_store);

static ssize_t
burstthresh_show(struct vbus_device *dev, struct vbus_device_attribute *attr,
	      char *buf)
{
	struct venetdev *priv = vdev_to_priv(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", priv->burst.thresh);
}

static ssize_t
burstthresh_store(struct vbus_device *dev, struct vbus_device_attribute *attr,
	       const char *buf, size_t count)
{
	struct venetdev *priv = vdev_to_priv(dev);
	int val = -1;

	if (count > 0)
		sscanf(buf, "%d", &val);

	if (val >= 0)
		priv->burst.thresh = val;

	return count;
}

struct vbus_device_attribute attr_burstthresh =
	__ATTR(burstthresh, S_IRUGO | S_IWUSR, burstthresh_show, burstthresh_store);

static ssize_t
txmitigation_show(struct vbus_device *dev, struct vbus_device_attribute *attr,
	      char *buf)
{
	struct venetdev *priv = vdev_to_priv(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", priv->txmitigation);
}

static ssize_t
txmitigation_store(struct vbus_device *dev, struct vbus_device_attribute *attr,
	       const char *buf, size_t count)
{
	struct venetdev *priv = vdev_to_priv(dev);
	int val = -1;

	if (count > 0)
		sscanf(buf, "%d", &val);

	if (val >= 0)
		priv->txmitigation = val;

	return count;
}

struct vbus_device_attribute attr_txmitigation =
	__ATTR(txmitigation, S_IRUGO | S_IWUSR, txmitigation_show, txmitigation_store);

ssize_t
zcthresh_show(struct vbus_device *dev, struct vbus_device_attribute *attr,
	      char *buf)
{
	struct venetdev *priv = vdev_to_priv(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", priv->zcthresh);
}

ssize_t
zcthresh_store(struct vbus_device *dev, struct vbus_device_attribute *attr,
	       const char *buf, size_t count)
{
	struct venetdev *priv = vdev_to_priv(dev);
	int val = -1;

	if (count > 0)
		sscanf(buf, "%d", &val);

	if (val >= 0)
		priv->zcthresh = val;

	return count;
}

struct vbus_device_attribute attr_zcthresh =
	__ATTR(zcthresh, S_IRUGO | S_IWUSR, zcthresh_show, zcthresh_store);

ssize_t
ifname_show(struct vbus_device *dev, struct vbus_device_attribute *attr,
	   char *buf)
{
	struct venetdev *priv = vdev_to_priv(dev);

	if (!priv->netif.enabled)
		return sprintf(buf, "<disabled>\n");

	return snprintf(buf, PAGE_SIZE, "%s\n", priv->netif.dev->name);
}

struct vbus_device_attribute attr_ifname =
	__ATTR_RO(ifname);

