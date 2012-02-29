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
#include <linux/if_macvlan.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>

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

struct venetmacv_netdev {
	struct macvlan_dev mvdev;
	const struct net_device_ops *macvlan_netdev_ops;
	struct venetmacv *vdev;
};

struct venetmacv {
	struct venetmacv_netdev *mdev;
	struct venetdev dev;
	unsigned char macv_ifname[IFNAMSIZ];
};

static struct venetmacv_netdev *find_macvenet(char *ifname);

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

static int venetmacv_forward(struct net_device *dev, struct sk_buff *skb)
{
	struct venetmacv_netdev *priv = netdev_priv(dev);
	struct venetmacv *macv = priv->vdev;
	int err;

	if (!macv) {
		PDEBUG("venetmacv_receive: vbus dev not connected \
			- dropping..\n");
		return NET_RX_DROP;
	}

	if (netif_queue_stopped(skb->dev)) {
		PDEBUG("venetmacv_receive: queue congested - dropping..\n");
		macv->dev.netif.stats.tx_dropped++;
		return NET_RX_DROP;
	}
	err = skb_linearize(skb);
	if (unlikely(err)) {
		printk(KERN_WARNING "venetmacv_receive: linearize failure\n");
		kfree_skb(skb);
		return -1;
	}
	return venetdev_xmit(skb, &macv->dev);
}

static int venetmacv_receive(struct sk_buff *skb)
{
	skb_push(skb, ETH_HLEN);
	return venetmacv_forward(skb->dev, skb);
}

static void
venetmacv_vlink_release(struct vbus_connection *conn)
{
	venetdev_vlink_release(conn);
}

static void
venetmacv_vlink_up(struct venetdev *vdev)
{
	int ret;

	if (vdev->netif.link) {
		rtnl_lock();
		ret = dev_open(vdev->netif.dev);
		rtnl_unlock();
		if (ret)
			printk(KERN_ERR "macvlan_open failed %d!\n", ret);
	}
}

static void
venetmacv_vlink_down(struct venetdev *vdev)
{
	int ret;

	if (vdev->netif.link) {
		rtnl_lock();
		ret = dev_close(vdev->netif.dev);
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

	if (!macv->mdev) {
		spin_unlock_irqrestore(&macv->dev.lock, flags);
		return -ENXIO;
	}

	spin_unlock_irqrestore(&macv->dev.lock, flags);

	*conn = &macv->dev.vbus.conn;

	return;
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

	if (macv->mdev) {
		dev_put(macv->mdev->mvdev.dev);
		macv->mdev->vdev = NULL;
		macv->dev.netif.dev = NULL;
		macv->mdev = NULL;
	}

}


static struct vbus_device_ops venetmacv_device_ops = {
	.bus_connect = venetmacv_device_bus_connect,
	.bus_disconnect = venetmacv_device_bus_disconnect,
	.release = venetmacv_device_release,
};

#define VENETMACV_TYPE "venet-macvlan"
static ssize_t
macv_ifname_store(struct vbus_device *dev, struct vbus_device_attribute *attr,
				const char *buf, size_t count)
{
	struct venetmacv *macv = vbusdev_to_macv(dev);
	size_t len;

	len = strlen(buf);

	if (len >= IFNAMSIZ)
		return -EINVAL;

	if (macv->dev.vbus.opened)
		return -EINVAL;

	memcpy(macv->macv_ifname, buf, count);

	/* remove trailing newline if present */
	if (macv->macv_ifname[count-1] == '\n')
		macv->macv_ifname[count-1] = '\0';

	if (macv->mdev) {
		dev_put(macv->mdev->mvdev.dev);
		macv->mdev = NULL;
	}

	macv->mdev = find_macvenet(macv->macv_ifname);

	if (!macv->mdev)
		return -ENXIO;

	macv->mdev->vdev = macv;
	macv->dev.netif.dev = macv->mdev->mvdev.dev;

	return len;
}

static ssize_t
macv_ifname_show(struct vbus_device *dev, struct vbus_device_attribute *attr,
			   char *buf)
{
	struct venetmacv *priv = vbusdev_to_macv(dev);

	return snprintf(buf, PAGE_SIZE, "%s\n", priv->macv_ifname);
}

static struct vbus_device_attribute attr_macv_ifname =
__ATTR(macv_ifname, S_IRUGO | S_IWUSR, macv_ifname_show, macv_ifname_store);

static ssize_t
clientmac_store(struct vbus_device *dev, struct vbus_device_attribute *attr,
		const char *buf, size_t count)
{
	struct venetmacv *macv = vbusdev_to_macv(dev);
	const struct net_device_ops *ops;
	struct sockaddr saddr;
	int ret;

	ret = attr_cmac.store(dev, attr, buf, count);

	if (ret == count && macv->mdev) {
		ops = macv->mdev->macvlan_netdev_ops;
		memcpy(saddr.sa_data, buf, ETH_ALEN);
		ops->ndo_set_mac_address(macv->dev.netif.dev, (void *)&saddr);
	}

	return ret;
}

static struct vbus_device_attribute attr_clientmac =
	__ATTR(client_mac, S_IRUGO | S_IWUSR, client_mac_show, clientmac_store);


static ssize_t
macv_enabled_show(struct vbus_device *dev, struct vbus_device_attribute *attr,
		  char *buf)
{
	struct venetdev *priv = vdev_to_priv(dev);

	return snprintf(buf, PAGE_SIZE, "%d\n", priv->netif.enabled);
}

static ssize_t
macv_enabled_store(struct vbus_device *dev, struct vbus_device_attribute *attr,
		   const char *buf, size_t count)
{
	struct venetdev *priv = vdev_to_priv(dev);
	struct venetmacv *macv = vbusdev_to_macv(dev);
	const struct net_device_ops *ops = macv->mdev->macvlan_netdev_ops;
	struct sockaddr saddr;
	int enabled = -1;
	int ret = 0;

	/* the following check is redundant, just being safe */
	if (!priv->netif.dev || !macv->mdev)
		return -ENODEV;

	if (count > 0)
		sscanf(buf, "%d", &enabled);

	if (enabled != 0 && enabled != 1)
		return -EINVAL;

	if (enabled && !priv->netif.enabled) {
		memcpy(saddr.sa_data, priv->cmac, ETH_ALEN);
		rtnl_lock();
		venetdev_open(priv);
		ops->ndo_set_mac_address(priv->netif.dev, (void *)&saddr);
		rtnl_unlock();
	}

	if (!enabled && priv->netif.enabled) {
		rtnl_lock();
		venetdev_stop(priv);
		rtnl_unlock();
	}

	if (ret < 0)
		return ret;

	priv->netif.enabled = enabled;

	return count;
}

static struct vbus_device_attribute attr_macv_enabled =
	__ATTR(enabled, S_IRUGO | S_IWUSR, macv_enabled_show,
		macv_enabled_store);

static struct attribute *attrs[] = {
	&attr_clientmac.attr,
	&attr_macv_enabled.attr,
	&attr_burstthresh.attr,
	&attr_txmitigation.attr,
	&attr_ifname.attr,
	&attr_macv_ifname.attr,
	NULL,
};

static struct attribute_group venetmacv_attr_group = {
	.attrs = attrs,
};

static int
venetmacv_netdev_open(struct net_device *dev)
{
	struct venetmacv_netdev *priv = netdev_priv(dev);

	return priv->macvlan_netdev_ops->ndo_open(dev);
}

static int
venetmacv_netdev_stop(struct net_device *dev)
{
	struct venetmacv_netdev *priv = netdev_priv(dev);

	return priv->macvlan_netdev_ops->ndo_stop(dev);
}

/*
 * out routine for macvlan
 */
static int
venetmacv_out(struct venetdev *vdev, struct sk_buff *skb)
{
	struct venetmacv *macv = venetdev_to_macv(vdev);
	struct venetmacv_netdev *priv = NULL;

	if (!macv->mdev)
		return -EIO;

	priv = netdev_priv(vdev->netif.dev);
	skb->dev = priv->mvdev.dev;
	skb->protocol = eth_type_trans(skb, skb->dev);
	skb_push(skb, ETH_HLEN);
	return priv->macvlan_netdev_ops->ndo_start_xmit(skb, skb->dev);
}

static int
venetmacv_netdev_tx(struct sk_buff *skb, struct net_device *dev)
{
	/* this function should generally not be used
	   the out routine is used by the venetdevice
	   for dequeuing and transmitting frames from
	   guest/userspace context */
	struct venetmacv_netdev *priv = netdev_priv(dev);
	return venetmacv_out(&priv->vdev->dev, skb);
}

static struct net_device_stats *
venetmacv_netdev_stats(struct net_device *dev)
{
	struct venetmacv_netdev *priv = netdev_priv(dev);
	struct venetmacv *macv = priv->vdev;

	/* return netdev's stats block when vbus
	   device is unconnected - this is ugly */
	if (macv)
		return venetdev_get_stats(&macv->dev);
	else
		return &dev->stats;
}

static int venetmacv_set_mac_address(struct net_device *dev, void *p)
{
	struct venetmacv_netdev *priv = netdev_priv(dev);
	struct venetdev *vdev = &priv->vdev->dev;
	struct sockaddr *saddr = p;
	int ret;

	ret = priv->macvlan_netdev_ops->ndo_set_mac_address(dev, p);

	if (!ret)
		memcpy(vdev->cmac, saddr->sa_data, ETH_ALEN);

	return ret;
}

static int venetmacv_change_mtu(struct net_device *dev, int new_mtu)
{
	struct venetmacv_netdev *priv = netdev_priv(dev);

	return priv->macvlan_netdev_ops->ndo_change_mtu(dev, new_mtu);
}

static void venetmacv_change_rx_flags(struct net_device *dev, int change)
{
	struct venetmacv_netdev *priv = netdev_priv(dev);

	priv->macvlan_netdev_ops->ndo_change_rx_flags(dev, change);
}

static void venetmacv_set_multicast_list(struct net_device *dev)
{
	struct venetmacv_netdev *priv = netdev_priv(dev);

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
};

static int macvenet_newlink(struct net *src_net, struct net_device *dev,
			    struct nlattr *tb[], struct nlattr *data[])
{
	struct venetmacv_netdev *priv = netdev_priv(dev);
	int err;

	err = macvlan_common_newlink(src_net, dev, tb, data,
				venetmacv_receive, venetmacv_forward);
	if (err)
		goto out1;

	priv->macvlan_netdev_ops = dev->netdev_ops;
	dev->netdev_ops = &venetmacv_netdev_ops;

	return 0;

out1:
	return err;
}

static void macvenet_dellink(struct net_device *dev, struct list_head *head)
{
	struct venetmacv_netdev *priv = netdev_priv(dev);
	struct venetmacv *vdev = priv->vdev;

	macvlan_dellink(dev, NULL);
	priv->mvdev.receive = netif_rx;
	priv->mvdev.forward = dev_forward_skb;
	if (vdev) {
		dev_put(dev);
		vdev->dev.netif.dev = NULL;
		vdev->mdev = NULL;
		if (vdev->dev.netif.enabled) {
			venetdev_stop(&vdev->dev);
			vdev->dev.netif.enabled = 0;
		}
	}
}

static void macvenet_setup(struct net_device *dev)
{
	struct venetmacv_netdev *priv = netdev_priv(dev);
	memset(priv, 0, sizeof(*priv));
	macvlan_setup(dev);
}

static struct venetmacv_netdev *find_macvenet(char *ifname)
{
	struct venetmacv_netdev *macv = NULL;
	struct net_device *dev = NULL;
	struct net *net = current->nsproxy->net_ns;

	if (strncmp("macvenet", ifname, 8))
		return NULL;

	dev = dev_get_by_name(net, ifname);

	if (dev)
		macv = netdev_priv(dev);

	return macv;
}

static struct rtnl_link_ops venetmacv_link_ops __read_mostly = {
	.kind = "macvenet",
	.priv_size = sizeof(struct venetmacv_netdev),
	.setup = macvenet_setup,
	.validate = macvlan_validate,
	.newlink = macvenet_newlink,
	.dellink = macvenet_dellink,
};

/*
 * This is called whenever the admin instantiates our devclass via
 * "mkdir /config/vbus/devices/$(inst)/venet-tap"
 */
static int
venetmacv_device_create(struct vbus_devclass *dc,
						struct vbus_device **vdev)
{
	struct venetmacv *priv;
	struct vbus_device *_vdev;

	priv = kmalloc(sizeof(*priv), GFP_KERNEL);

	if (!priv)
		return -ENOMEM;

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

	*vdev = _vdev;

	venetdev_common_init(&priv->dev);
	priv->dev.netif.out = venetmacv_out;

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
	int err = 0;

	err = rtnl_link_register(&venetmacv_link_ops);

	if (err < 0)
		goto out;

	err = vbus_devclass_register(&venetmacv_devclass);

	if (err)
		goto out2;

	return 0;
out2:
	rtnl_link_unregister(&venetmacv_link_ops);

out:
	return err;
}

static void __exit venetmacv_cleanup(void)
{
	rtnl_link_unregister(&venetmacv_link_ops);
	vbus_devclass_unregister(&venetmacv_devclass);
}

module_init(venetmacv_init);
module_exit(venetmacv_cleanup);

