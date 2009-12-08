/*
 * venet-macvlan - A Vbus based 802.x virtual network device that utilizes
 *                 a macvlan device as the backend
 *
 * Copyright (C) 2009 Novell, Patrick Mullaney <pmullaney@novell.com>
 *
 * Based on the venet-tap driver from Gregory Haskins
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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>

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
#include <linux/ktime.h>
#include <linux/macvlan.h>

#include "venetdevice.h"

#include <linux/in6.h>
#include <asm/checksum.h>

MODULE_AUTHOR("Patrick Mullaney");
MODULE_LICENSE("GPL");

#undef PDEBUG             /* undef it, just in case */
#ifdef VENETMACVLAN_DEBUG
#  define PDEBUG(fmt, args...) printk(KERN_DEBUG "venet-tap: " fmt, ## args)
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

struct venetmacv {
	struct macvlan_dev mdev;
	unsigned char ll_ifname[IFNAMSIZ];
	struct venetdev dev;
	const struct net_device_ops *macvlan_netdev_ops;
};

static inline struct venetmacv *conn_to_macv(struct vbus_connection *conn)
{
	return container_of(conn, struct venetmacv, dev.vbus.conn);
}

static inline
struct venetmacv *venetdev_to_macv(struct venetdev *vdev)
{
	return container_of(vdev, struct venetmacv, dev);
}

static inline
struct venetmacv *vbusintf_to_macv(struct vbus_device_interface *intf)
{
	return container_of(intf, struct venetmacv, dev.vbus.intf);
}

static inline
struct venetmacv *vbusdev_to_macv(struct vbus_device *vdev)
{
	return container_of(vdev, struct venetmacv, dev.vbus.dev);
}

static int
venetmacv_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct venetmacv *priv = netdev_priv(dev);

	return venetdev_xmit(skb, &priv->dev);
}

static int venetmacv_receive(struct sk_buff *skb)
{
	struct venetmacv *priv = netdev_priv(skb->dev);
	int err;

	if (netif_queue_stopped(skb->dev)) {
		PDEBUG("venetmacv_receive: queue congested - dropping..\n");
		priv->dev.netif.stats.tx_dropped++;
		return NET_RX_DROP;
	}
	err = skb_linearize(skb);
	if (unlikely(err)) {
		printk(KERN_WARNING "venetmacv_receive: linearize failure\n");
		kfree_skb(skb);
		return -1;
	}
	skb_push(skb, ETH_HLEN);
	return venetmacv_tx(skb, skb->dev);
}

static void
venetmacv_vlink_release(struct vbus_connection *conn)
{
	struct venetmacv *macv = conn_to_macv(conn);
	macvlan_unlink_lowerdev(macv->mdev.dev);
	venetdev_vlink_release(conn);
}

static void
venetmacv_vlink_up(struct venetdev *vdev)
{
	struct venetmacv *macv = venetdev_to_macv(vdev);
	int ret;

	if (vdev->netif.link) {
		rtnl_lock();
		ret = macv->macvlan_netdev_ops->ndo_open(vdev->netif.dev);
		rtnl_unlock();
		if (ret)
			printk(KERN_ERR "macvlan_open failed %d!\n", ret);
	}
}

static void
venetmacv_vlink_down(struct venetdev *vdev)
{
	struct venetmacv *macv = venetdev_to_macv(vdev);
	int ret;

	if (vdev->netif.link) {
		rtnl_lock();
		ret = macv->macvlan_netdev_ops->ndo_stop(vdev->netif.dev);
		rtnl_unlock();
		if (ret)
			printk(KERN_ERR "macvlan close failed %d!\n", ret);
	}
}

static int
venetmacv_vlink_call(struct vbus_connection *conn,
					 unsigned long func,
					 void *data,
					 unsigned long len,
					 unsigned long flags)
{
	struct venetdev *priv = conn_to_priv(conn);
	int ret;

	switch (func) {
	case VENET_FUNC_LINKUP:
		venetmacv_vlink_up(priv);
		break;
	case VENET_FUNC_LINKDOWN:
		venetmacv_vlink_down(priv);
		break;
	}
	ret = venetdev_vlink_call(conn, func, data, len, flags);
	return ret;
}

static struct vbus_connection_ops venetmacv_vbus_link_ops = {
	.call    = venetmacv_vlink_call,
	.shm     = venetdev_vlink_shm,
	.close   = venetdev_vlink_close,
	.release = venetmacv_vlink_release,
};

/*
 * This is called whenever a driver wants to open our device_interface
 * for communication.  The connection is represented by a
 * vbus_connection object.  It is up to the implementation to decide
 * if it allows more than one connection at a time.  This simple example
 * does not.
 */

static int
venetmacv_intf_connect(struct vbus_device_interface *intf,
					   struct vbus_memctx *ctx,
					   int version,
					   struct vbus_connection **conn)
{
	struct venetmacv *macv = vbusintf_to_macv(intf);
	unsigned long flags;
	int ret;

	PDEBUG("connect\n");

	if (version != VENET_VERSION)
		return -EINVAL;

	spin_lock_irqsave(&macv->dev.lock, flags);

	/*
	 * We only allow one connection to this device
	 */
	if (macv->dev.vbus.opened) {
		spin_unlock_irqrestore(&macv->dev.lock, flags);
		return -EBUSY;
	}

	kobject_get(intf->dev->kobj);

	vbus_connection_init(&macv->dev.vbus.conn, &venetmacv_vbus_link_ops);

	macv->dev.vbus.opened = true;
	macv->dev.vbus.ctx = ctx;

	vbus_memctx_get(ctx);

	if (!macv->mdev.lowerdev) {
		spin_unlock_irqrestore(&macv->dev.lock, flags);
		return -ENXIO;
	}

	ret = macvlan_link_lowerdev(macv->mdev.dev, macv->mdev.lowerdev);

	if (ret) {
		spin_unlock_irqrestore(&macv->dev.lock, flags);
		printk(KERN_ERR "macvlan_link_lowerdev: failed\n");
		return -ENXIO;
	}

	macvlan_transfer_operstate(macv->mdev.dev);

	macv->mdev.receive = venetmacv_receive;

	spin_unlock_irqrestore(&macv->dev.lock, flags);

	*conn = &macv->dev.vbus.conn;

	return 0;
}

static void
venetmacv_intf_release(struct vbus_device_interface *intf)
{
	kobject_put(intf->dev->kobj);
}

static struct vbus_device_interface_ops venetmacv_device_interface_ops = {
	.connect = venetmacv_intf_connect,
	.release = venetmacv_intf_release,
};

/*
 * This is called whenever the admin creates a symbolic link between
 * a bus in /config/vbus/buses and our device.  It represents a bus
 * connection.  Your device can chose to allow more than one bus to
 * connect, or it can restrict it to one bus.  It can also choose to
 * register one or more device_interfaces on each bus that it
 * successfully connects to.
 *
 * This example device only registers a single interface
 */
static int
venetmacv_device_bus_connect(struct vbus_device *dev, struct vbus *vbus)
{
	struct venetdev *priv = vdev_to_priv(dev);
	struct vbus_device_interface *intf = &priv->vbus.intf;

	/* We only allow one bus to connect */
	if (priv->vbus.connected)
		return -EBUSY;

	kobject_get(dev->kobj);

	intf->name = "default";
	intf->type = VENET_TYPE;
	intf->ops = &venetmacv_device_interface_ops;

	priv->vbus.connected = true;

	/*
	 * Our example only registers one interface.  If you need
	 * more, simply call interface_register() multiple times
	 */
	return vbus_device_interface_register(dev, vbus, intf);
}

/*
 * This is called whenever the admin removes the symbolic link between
 * a bus in /config/vbus/buses and our device.
 */
static int
venetmacv_device_bus_disconnect(struct vbus_device *dev, struct vbus *vbus)
{
	struct venetdev *priv = vdev_to_priv(dev);
	struct vbus_device_interface *intf = &priv->vbus.intf;

	if (!priv->vbus.connected)
		return -EINVAL;

	vbus_device_interface_unregister(intf);

	priv->vbus.connected = false;
	kobject_put(dev->kobj);

	return 0;
}

static void
venetmacv_device_release(struct vbus_device *dev)
{
	struct venetmacv *macv = vbusdev_to_macv(dev);

	if (macv->mdev.lowerdev) {
		dev_put(macv->mdev.lowerdev);
		macv->mdev.lowerdev = NULL;
	}

	venetdev_netdev_unregister(&macv->dev);
	free_netdev(macv->mdev.dev);
}


static struct vbus_device_ops venetmacv_device_ops = {
	.bus_connect = venetmacv_device_bus_connect,
	.bus_disconnect = venetmacv_device_bus_disconnect,
	.release = venetmacv_device_release,
};

#define VENETMACV_TYPE "venet-macvlan"
static ssize_t
ll_ifname_store(struct vbus_device *dev, struct vbus_device_attribute *attr,
				const char *buf, size_t count)
{
	struct venetmacv *priv = vbusdev_to_macv(dev);
	size_t len;

	len = strlen(buf);

	if (len >= IFNAMSIZ)
		return -EINVAL;

	if (priv->dev.vbus.opened)
		return -EINVAL;

	memcpy(priv->ll_ifname, buf, count);

	/* remove trailing newline if present */
	if (priv->ll_ifname[count-1] == '\n')
		priv->ll_ifname[count-1] = '\0';

	if (priv->mdev.lowerdev) {
		dev_put(priv->mdev.lowerdev);
		priv->mdev.lowerdev = NULL;
	}

	priv->mdev.lowerdev = dev_get_by_name(dev_net(priv->mdev.dev),
						priv->ll_ifname);

	if (!priv->mdev.lowerdev)
		return -ENXIO;

	return len;
}

static ssize_t
ll_ifname_show(struct vbus_device *dev, struct vbus_device_attribute *attr,
			   char *buf)
{
	struct venetmacv *priv = vbusdev_to_macv(dev);

	return snprintf(buf, PAGE_SIZE, "%s\n", priv->ll_ifname);
}

static struct vbus_device_attribute attr_ll_ifname =
__ATTR(ll_ifname, S_IRUGO | S_IWUSR, ll_ifname_show, ll_ifname_store);

static ssize_t
clientmac_store(struct vbus_device *dev, struct vbus_device_attribute *attr,
		const char *buf, size_t count)
{
	struct venetmacv *macv = vbusdev_to_macv(dev);
	int ret;

	ret = attr_cmac.store(dev, attr, buf, count);

	if (ret == count)
		memcpy(macv->mdev.dev->dev_addr, macv->dev.cmac, ETH_ALEN);

	return ret;
}

static struct vbus_device_attribute attr_clientmac =
	__ATTR(client_mac, S_IRUGO | S_IWUSR, client_mac_show, clientmac_store);


static ssize_t
macv_enabled_store(struct vbus_device *dev, struct vbus_device_attribute *attr,
		   const char *buf, size_t count)
{
	struct venetmacv *macv = vbusdev_to_macv(dev);
	int ret;

	if (!macv->mdev.lowerdev)
		return -ENXIO;

	ret = attr_enabled.store(dev, attr, buf, count);

	return ret;
}

static struct vbus_device_attribute attr_macv_enabled =
	__ATTR(enabled, S_IRUGO | S_IWUSR, enabled_show, macv_enabled_store);

static struct attribute *attrs[] = {
	&attr_clientmac.attr,
	&attr_macv_enabled.attr,
	&attr_burstthresh.attr,
	&attr_txmitigation.attr,
	&attr_ifname.attr,
	&attr_ll_ifname.attr,
	NULL,
};

static struct attribute_group venetmacv_attr_group = {
	.attrs = attrs,
};

static int
venetmacv_netdev_open(struct net_device *dev)
{
	struct venetmacv *priv = netdev_priv(dev);
	int ret = 0;

	venetdev_open(&priv->dev);

	if (priv->dev.vbus.link) {
		ret = priv->macvlan_netdev_ops->ndo_open(priv->mdev.dev);
	}

	return ret;
}

static int
venetmacv_netdev_stop(struct net_device *dev)
{
	struct venetmacv *priv = netdev_priv(dev);
	int needs_stop = false;
	int ret = 0;

	if (priv->dev.netif.link)
		needs_stop = true;

	venetdev_stop(&priv->dev);

	if (priv->dev.vbus.link && needs_stop)
		ret = priv->macvlan_netdev_ops->ndo_stop(dev);

	return ret;
}

static void
venetmacv_netdev_uninit(struct net_device *dev)
{
	struct venetmacv *macv = netdev_priv(dev);

	if (macv->mdev.lowerdev) {
		dev_put(macv->mdev.lowerdev);
		macv->mdev.lowerdev = NULL;
		memset(macv->ll_ifname, '\0', IFNAMSIZ);
	}

	macv->dev.netif.enabled = 0;
}

/*
 * out routine for macvlan
 */

static int
venetmacv_out(struct venetdev *vdev, struct sk_buff *skb)
{
	struct venetmacv *macv = venetdev_to_macv(vdev);
	skb->dev = macv->mdev.lowerdev;
	skb->protocol = eth_type_trans(skb, macv->mdev.lowerdev);
	skb_push(skb, ETH_HLEN);
	return macv->macvlan_netdev_ops->ndo_start_xmit(skb, macv->mdev.dev);
}

static int
venetmacv_netdev_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct venetmacv *priv = netdev_priv(dev);

	return venetmacv_out(&priv->dev, skb);
}

static struct net_device_stats *
venetmacv_netdev_stats(struct net_device *dev)
{
	struct venetmacv *priv = netdev_priv(dev);
	return venetdev_get_stats(&priv->dev);
}

static int venetmacv_set_mac_address(struct net_device *dev, void *p)
{
	struct venetmacv *priv = netdev_priv(dev);
	int ret;

	ret = priv->macvlan_netdev_ops->ndo_set_mac_address(dev, p);

	if (!ret)
		memcpy(priv->dev.cmac, p, ETH_ALEN);

	return ret;
}

static int venetmacv_change_mtu(struct net_device *dev, int new_mtu)
{
	struct venetmacv *priv = netdev_priv(dev);

	return priv->macvlan_netdev_ops->ndo_change_mtu(dev, new_mtu);
}

static void venetmacv_change_rx_flags(struct net_device *dev, int change)
{
	struct venetmacv *priv = netdev_priv(dev);

	priv->macvlan_netdev_ops->ndo_change_rx_flags(dev, change);
}

static void venetmacv_set_multicast_list(struct net_device *dev)
{
	struct venetmacv *priv = netdev_priv(dev);

	priv->macvlan_netdev_ops->ndo_set_multicast_list(dev);
}

static struct net_device_ops venetmacv_netdev_ops = {
	.ndo_open               = venetmacv_netdev_open,
	.ndo_stop               = venetmacv_netdev_stop,
	.ndo_set_config         = venetdev_netdev_config,
	.ndo_change_mtu         = venetmacv_change_mtu,
	.ndo_set_mac_address    = venetmacv_set_mac_address,
	.ndo_change_rx_flags    = venetmacv_change_rx_flags,
	.ndo_set_multicast_list = venetmacv_set_multicast_list,
	.ndo_validate_addr      = eth_validate_addr,
	.ndo_start_xmit         = venetmacv_netdev_tx,
	.ndo_do_ioctl           = venetdev_netdev_ioctl,
	.ndo_get_stats          = venetmacv_netdev_stats,
	.ndo_uninit             = venetmacv_netdev_uninit,
};

/*
 * This is called whenever the admin instantiates our devclass via
 * "mkdir /config/vbus/devices/$(inst)/venet-tap"
 */
static int
venetmacv_device_create(struct vbus_devclass *dc,
						struct vbus_device **vdev)
{
	struct net_device *dev;
	struct venetmacv *priv;
	struct vbus_device *_vdev;

	dev = alloc_netdev(sizeof(struct venetmacv), "macvenet%d",
					   macvlan_setup);


	dev->destructor = NULL;

	if (!dev)
		return -ENOMEM;

	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(*priv));

	spin_lock_init(&priv->dev.lock);
	random_ether_addr(priv->dev.cmac);
	memcpy(priv->dev.hmac, priv->dev.cmac, ETH_ALEN);

	/*
	 * vbus init
	 */
	_vdev = &priv->dev.vbus.dev;

	_vdev->type            = VENETMACV_TYPE;
	_vdev->ops             = &venetmacv_device_ops;
	_vdev->attrs           = &venetmacv_attr_group;

	venetdev_init(&priv->dev, dev);

	priv->mdev.dev = dev;
	priv->dev.netif.out = venetmacv_out;

	priv->macvlan_netdev_ops = dev->netdev_ops;
	dev->netdev_ops = &venetmacv_netdev_ops;

	*vdev = _vdev;

	return 0;
}

static struct vbus_devclass_ops venetmacv_devclass_ops = {
	.create = venetmacv_device_create,
};

static struct vbus_devclass venetmacv_devclass = {
	.name = VENETMACV_TYPE,
	.ops = &venetmacv_devclass_ops,
	.owner = THIS_MODULE,
};

static int __init venetmacv_init(void)
{
	return vbus_devclass_register(&venetmacv_devclass);
}

static void __exit venetmacv_cleanup(void)
{
	vbus_devclass_unregister(&venetmacv_devclass);
}

module_init(venetmacv_init);
module_exit(venetmacv_cleanup);

