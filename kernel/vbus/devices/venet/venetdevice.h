
/*
 * Copyright 2009 Novell.  All Rights Reserved.
 *
 * Virtual-Ethernet adapter
 *
 * Author:
 *      Gregory Haskins <ghaskins@novell.com>
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

#ifndef _LINUX_VENETDEVICE_H
#define _LINUX_VENETDEVICE_H

#include <linux/venet.h>
#include <linux/list.h>

struct venetdev_queue {
	struct ioq              *queue;
	struct ioq_notifier      notifier;
};

struct venetdev;

#define MAX_VSG_DESC_SIZE VSG_DESC_SIZE(MAX_SKB_FRAGS)

enum {
	RX_SCHED,
	TX_SCHED,
	TX_NETIF_CONGESTED,
	TX_IOQ_CONGESTED,
};

struct venetdev {
	spinlock_t                   lock;
	unsigned char                hmac[ETH_ALEN]; /* host-mac */
	unsigned char                cmac[ETH_ALEN]; /* client-mac */
	struct task_struct          *rxthread;
	struct task_struct          *txthread;
	unsigned long                flags;

	struct {
		struct net_device           *dev;
		struct net_device_stats      stats;
		int (*out)(struct venetdev *, struct sk_buff *);
		struct {
			struct sk_buff_head  list;
			size_t               len;
			int                  irqdepth;
		} txq;
		struct {
			atomic_t             outstanding;
			size_t               completed;
			wait_queue_head_t    wq;
		} rxq;
		bool                         enabled;
		bool                         link;
	} netif;

	struct {
		struct vbus_device           dev;
		struct vbus_device_interface intf;
		struct vbus_connection       conn;
		struct vbus_memctx          *ctx;
		struct venetdev_queue        rxq;
		struct venetdev_queue        txq;

		struct sk_buff *(*import)(struct venetdev *, void *, int);
		int (*export)(struct venetdev *, struct ioq_ring_desc *,
			      struct sk_buff *);

		wait_queue_head_t            rx_empty;
		struct {
			char                 buf[MAX_VSG_DESC_SIZE];
			size_t               len;
			bool                 enabled;
		} sg;
		struct {
			struct vbus_shm     *shm;
			bool                 enabled;
		} pmtd;
		struct {
			spinlock_t             lock;
			struct vbus_shm       *shm;
			struct venetdev_queue  queue;
			bool                   enabled;
			bool                   linkstate;
			bool                   txc;
		} evq;
		struct {
			struct vbus_shm       *shm;
			struct venetdev_queue  pageq;
			bool                   available;
			bool                   enabled;
		} l4ro;
		bool                         connected;
		bool                         opened;
		bool                         link;
	} vbus;

	struct {
		int                          thresh;
		ktime_t                      expires;
	} burst;
	int                                  txmitigation;
	int                                  zcthresh;
};

static inline struct venetdev *conn_to_priv(struct vbus_connection *conn)
{
	return container_of(conn, struct venetdev, vbus.conn);
}

static inline struct venetdev *intf_to_priv(struct vbus_device_interface *intf)
{
	return container_of(intf, struct venetdev, vbus.intf);
}

static inline struct venetdev *vdev_to_priv(struct vbus_device *vdev)
{
	return container_of(vdev, struct venetdev, vbus.dev);
}

int venetdev_netdev_open(struct net_device *dev);
int venetdev_netdev_stop(struct net_device *dev);
int venetdev_netdev_config(struct net_device *dev, struct ifmap *map);
int venetdev_change_mtu(struct net_device *dev, int new_mtu);
int venetdev_netdev_tx(struct sk_buff *skb, struct net_device *dev);
int venetdev_netdev_ioctl(struct net_device *dev, struct ifreq *rq,
						   int cmd);
struct net_device_stats *venetdev_netdev_stats(struct net_device *dev);

int venetdev_open(struct venetdev *dev);
int venetdev_stop(struct venetdev *dev);
int venetdev_xmit(struct sk_buff *skb, struct venetdev *dev);
struct net_device_stats *venetdev_get_stats(struct venetdev *dev);

static inline void venetdev_netdev_unregister(struct venetdev *priv)
{
	if (priv->netif.enabled) {
		venetdev_stop(priv);
		unregister_netdev(priv->netif.dev);
	}
}

int venetdev_vlink_call(struct vbus_connection *conn,
		    unsigned long func, void *data, unsigned long len,
		    unsigned long flags);
int venetdev_vlink_shm(struct vbus_connection *conn,
		   unsigned long id, struct vbus_shm *shm,
		   struct shm_signal *signal, unsigned long flags);
void  venetdev_vlink_release(struct vbus_connection *conn);
void  venetdev_vlink_close(struct vbus_connection *conn);
void venetdev_init(struct venetdev *vdev, struct net_device *dev);

extern struct vbus_device_attribute attr_cmac;
extern struct vbus_device_attribute attr_hmac;
extern struct vbus_device_attribute attr_enabled;
extern struct vbus_device_attribute attr_burstthresh;
extern struct vbus_device_attribute attr_ifname;
extern struct vbus_device_attribute attr_txmitigation;
extern struct vbus_device_attribute attr_zcthresh;

ssize_t enabled_store(struct vbus_device *dev,
		struct vbus_device_attribute *attr,
		 const char *buf, size_t count);
ssize_t enabled_show(struct vbus_device *dev,
			struct vbus_device_attribute *attr, char *buf);
ssize_t cmac_store(struct vbus_device *dev,
		struct vbus_device_attribute *attr,
		 const char *buf, size_t count);
ssize_t client_mac_show(struct vbus_device *dev,
			struct vbus_device_attribute *attr, char *buf);


#endif
