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

#define PMTD_POOL_ID 100

static void venetdev_tx_isr(struct ioq_notifier *notifier);
static int venetdev_rx_thread(void *__priv);
static int venetdev_tx_thread(void *__priv);

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
venetdev_netdev_open(struct net_device *dev)
{
	struct venetdev *priv = netdev_priv(dev);
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
		netif_carrier_off(dev);

	spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

int
venetdev_netdev_stop(struct net_device *dev)
{
	struct venetdev *priv = netdev_priv(dev);
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
 * Scatter-Gather support
 * ---------------------------
 */

/* assumes reference to priv->vbus.conn held */
static int
venetdev_sg_decode(struct venetdev *priv, void *ptr, int len)
{
	struct venet_sg *vsg = (struct venet_sg *)priv->vbus.sg.buf;
	int ret;

	PDEBUG("desc: %p/%d\n", ptr, len);

	if (unlikely(len < sizeof(*vsg) || len > MAX_VSG_DESC_SIZE)) {
		PDEBUG("invalid len: %d\n", len);
		return -1;
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
			return -1;
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
			return -1;
		}
	}

	PDEBUG("pmtd-pool:%p, vsg=%p\n", priv->vbus.pmtd.shm->ptr, vsg);

	if (len < VSG_DESC_SIZE(vsg->count)) {
		PDEBUG("%d < %d\n", len, VSG_DESC_SIZE(vsg->count));
		return -1;
	}

	if (vsg->flags & VENET_SG_FLAG_GSO) {
		/* GSO packets shall not exceed 64k frames */
		if (vsg->len > 65536)
			return -1;

	} else
		/*
		 * Non GSO type packets should be constrained by the MTU setting
		 * on the host
		 */
		if (vsg->len > (priv->netif.dev->mtu + ETH_HLEN))
			return -1;

	priv->vbus.sg.len = len;

	return vsg->len;
}

/*
 * venetdev_sg_import - import an skb in scatter-gather mode
 *
 * assumes reference to priv->vbus.conn held
 */
static int
venetdev_sg_import(struct venetdev *priv, struct sk_buff *skb,
		   void *ptr, int len)
{
	struct venet_sg *vsg = (struct venet_sg *)priv->vbus.sg.buf;
	struct vbus_memctx *ctx = priv->vbus.ctx;
	int remain = len;
	int ret;
	int i;

	PDEBUG("Importing %d bytes in %d segments\n", len, vsg->count);

	for (i = 0; i < vsg->count; i++) {
		struct venet_iov *iov = &vsg->iov[i];

		if (remain < iov->len)
			return -EINVAL;

		PDEBUG("Segment %d: %p/%d\n", i, iov->ptr, iov->len);

		ret = ctx->ops->copy_from(ctx, skb_tail_pointer(skb),
					 (void *)iov->ptr,
					 iov->len);
		if (ret)
			return -EFAULT;

		skb_put(skb, iov->len);
		remain -= iov->len;
	}

	if (vsg->flags & VENET_SG_FLAG_NEEDS_CSUM
	    && !skb_partial_csum_set(skb, vsg->csum.start, vsg->csum.offset))
		return -EINVAL;

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
			return -EINVAL;
		}

		if (vsg->flags & VENET_SG_FLAG_ECN)
			sinfo->gso_type |= SKB_GSO_TCP_ECN;

		sinfo->gso_size = vsg->gso.size;
		if (skb_shinfo(skb)->gso_size == 0) {
			PDEBUG("Illegal GSO size: %d\n", vsg->gso.size);
			priv->netif.stats.rx_frame_errors++;
			kfree_skb(skb);
			return -EINVAL;
		}

		/* Header must be checked, and gso_segs computed. */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;
	}

	return 0;
}

static struct venetdev_rx_ops venetdev_sg_rx_ops = {
	.decode = venetdev_sg_decode,
	.import = venetdev_sg_import,
};

/*
 * ---------------------------
 * Flat (non Scatter-Gather) support
 * ---------------------------
 */

/* assumes reference to priv->vbus.conn held */
static int
venetdev_flat_decode(struct venetdev *priv, void *ptr, int len)
{
	size_t maxlen = priv->netif.dev->mtu + ETH_HLEN;

	if (len > maxlen)
		return -1;

	/*
	 * If SG is *not* enabled, the length is simply the
	 * descriptor length
	 */

	return len;
}

/*
 * venetdev_rx_flat - import an skb in non scatter-gather mode
 *
 * assumes reference to priv->vbus.conn held
 */
static int
venetdev_flat_import(struct venetdev *priv, struct sk_buff *skb,
		     void *ptr, int len)
{
	struct vbus_memctx *ctx = priv->vbus.ctx;
	int ret;

	ret = ctx->ops->copy_from(ctx, skb_tail_pointer(skb), ptr, len);
	if (ret)
		return -EFAULT;

	skb_put(skb, len);

	return 0;
}

static struct venetdev_rx_ops venetdev_flat_rx_ops = {
	.decode = venetdev_flat_decode,
	.import = venetdev_flat_import,
};

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
	struct vbus_memctx         *ctx;
	int                         npackets = 0;
	int                         dirty = 0;
	struct ioq_iterator         iter;
	int                         ret;
	unsigned long               flags;
	struct vbus_connection     *conn;
	struct venetdev_rx_ops     *rx_ops;

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
	ctx = priv->vbus.ctx;

	rx_ops = priv->vbus.rx_ops;

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
		struct sk_buff *skb = NULL;
		int len;

		len = rx_ops->decode(priv,
				     (void *)iter.desc->ptr,
				     iter.desc->len);

		if (unlikely(len < 0)) {
			priv->netif.stats.rx_errors++;
			priv->netif.stats.rx_length_errors++;
			goto next;
		}

		skb = dev_alloc_skb(len + NET_IP_ALIGN);
		if (unlikely(!skb)) {
			printk(KERN_INFO "VENETTAP: skb alloc failed:"	\
			       " memory squeeze.\n");
			priv->netif.stats.rx_errors++;
			priv->netif.stats.rx_dropped++;
			goto next;
		}

		/* align IP on 16B boundary */
		skb_reserve(skb, NET_IP_ALIGN);

		ret = rx_ops->import(priv, skb, (void *)iter.desc->ptr, len);
		if (unlikely(ret < 0)) {
			priv->netif.stats.rx_errors++;
			goto next;
		}

		/* Maintain stats */
		npackets++;
		priv->netif.stats.rx_packets++;
		priv->netif.stats.rx_bytes += len;

		priv->netif.out(priv, skb);
next:
		dirty = 1;

		/* Advance the in-use head */
		ret = ioq_iter_pop(&iter, 0);
		BUG_ON(ret < 0);

		/* send up to N packets before sending tx-complete */
		if (!priv->txmitigation || !(npackets % priv->txmitigation)) {
			ioq_signal(ioq, 0);
			dirty = 0;
		}

	}

	PDEBUG("poll: %d packets received\n", npackets);

	if (dirty)
		ioq_signal(ioq, 0);

	/*
	 * If we processed all packets we're done, so reenable ints
	 */
	if (ioq_empty(ioq, ioq_idxtype_inuse)) {
		clear_bit(RX_SCHED, &priv->flags);
		ioq_notify_enable(ioq, 0);
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
		bool sent = false;

		skb = __skb_dequeue(&priv->netif.txq.list);
		if (!skb)
			break;

		spin_unlock_irqrestore(&priv->lock, flags);

		PDEBUG("tx-thread: sending %d bytes\n", skb->len);

		if (skb->len <= iter.desc->len) {
			ret = ctx->ops->copy_to(ctx, (void *)iter.desc->ptr,
					       skb->data, skb->len);
			if (!ret) {
				iter.desc->len = skb->len;

				npackets++;
				priv->netif.stats.tx_packets++;
				priv->netif.stats.tx_bytes += skb->len;

				ret = ioq_iter_push(&iter, 0);
				BUG_ON(ret < 0);

				sent = true;
			}
		}

		if (!sent)
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
venetdev_netdev_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct venetdev *priv = netdev_priv(dev);
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
		printk(KERN_ERR "VENETTAP: tx on link down\n");
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
venetdev_netdev_stats(struct net_device *dev)
{
	struct venetdev *priv = netdev_priv(dev);
	return &priv->netif.stats;
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
		priv->vbus.rx_ops = &venetdev_sg_rx_ops;
	}

	if (ret & VENET_CAP_PMTD)
		priv->vbus.pmtd.enabled = true;

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


void venetdev_init(struct venetdev *device, struct net_device *dev)
{
	device->vbus.rx_ops      = &venetdev_flat_rx_ops;
	init_waitqueue_head(&device->vbus.rx_empty);
	device->burst.thresh     = 0; /* microseconds, 0 = disabled */
	device->txmitigation     = 10; /* nr-packets, 0 = disabled */

	/*
	 * netif init
	 */
	skb_queue_head_init(&device->netif.txq.list);
	device->netif.txq.len = 0;

	device->netif.dev = dev;
	device->netif.out = venetdev_out;

	ether_setup(dev); /* assign some of the fields */

	memcpy(dev->dev_addr, device->hmac, ETH_ALEN);

	dev->features |= NETIF_F_HIGHDMA;

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

	PDEBUG("queue -> %p/%d attached\n", ioq, id);

	switch (id) {
	case VENET_QUEUE_RX:
		return venetdev_queue_init(&priv->vbus.txq, shm, signal,
					   venetdev_tx_isr);
	case VENET_QUEUE_TX:
		return venetdev_queue_init(&priv->vbus.rxq, shm, signal,
					   venetdev_rx_isr);
	case PMTD_POOL_ID:
		return venetdev_pmtd_init(priv, shm, signal);
	default:
		return -EINVAL;
	}

	return 0;
}

void
venetdev_vlink_close(struct vbus_connection *conn)
{
	struct venetdev *priv = conn_to_priv(conn);
	DEFINE_WAIT(wait);
	unsigned long flags;

	PDEBUG("connection closed\n");

	/* Block until all posted packets from the client have been processed */
	prepare_to_wait(&priv->vbus.rx_empty, &wait, TASK_UNINTERRUPTIBLE);

	while (test_bit(RX_SCHED, &priv->flags))
		schedule();

	finish_wait(&priv->vbus.rx_empty, &wait);

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
	priv->vbus.rx_ops = &venetdev_flat_rx_ops;
	priv->vbus.sg.len = 0;

	if (priv->vbus.pmtd.shm)
		vbus_shm_put(priv->vbus.pmtd.shm);
	priv->vbus.pmtd.shm = NULL;
	priv->vbus.pmtd.enabled = false;
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


static ssize_t
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

static ssize_t
client_mac_show(struct vbus_device *dev, struct vbus_device_attribute *attr,
	 char *buf)
{
	struct venetdev *priv = vdev_to_priv(dev);

	return sysfs_format_mac(buf, priv->cmac, ETH_ALEN);
}

struct vbus_device_attribute attr_cmac =
	__ATTR(client_mac, S_IRUGO | S_IWUSR, client_mac_show, cmac_store);

static ssize_t
enabled_show(struct vbus_device *dev, struct vbus_device_attribute *attr,
	 char *buf)
{
	struct venetdev *priv = vdev_to_priv(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", priv->netif.enabled);
}

static ssize_t
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

	if (enabled && !priv->netif.enabled)
		ret = register_netdev(priv->netif.dev);

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

