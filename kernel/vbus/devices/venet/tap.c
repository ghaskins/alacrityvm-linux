/*
 * venettap - A 802.x virtual network device based on the VBUS/IOQ interface
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

#include "venetdevice.h"

#include <linux/in6.h>
#include <asm/checksum.h>

MODULE_AUTHOR("Gregory Haskins");
MODULE_LICENSE("GPL");

#undef PDEBUG             /* undef it, just in case */
#ifdef VENETTAP_DEBUG
#  define PDEBUG(fmt, args...) printk(KERN_DEBUG "venet-tap: " fmt, ## args)
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

static struct vbus_connection_ops venettap_vbus_link_ops = {
	.call    = venetdev_vlink_call,
	.shm     = venetdev_vlink_shm,
	.close   = venetdev_vlink_close,
	.release = venetdev_vlink_release,
};

/*
 * This is called whenever a driver wants to open our device_interface
 * for communication.  The connection is represented by a
 * vbus_connection object.  It is up to the implementation to decide
 * if it allows more than one connection at a time.  This simple example
 * does not.
 */

static int
venettap_intf_connect(struct vbus_device_interface *intf,
		   struct vbus_memctx *ctx,
		   int version,
		   struct vbus_connection **conn)
{
	struct venetdev *priv = intf_to_priv(intf);
	unsigned long flags;

	PDEBUG("connect\n");

	if (version != VENET_VERSION)
		return -EINVAL;

	spin_lock_irqsave(&priv->lock, flags);

	/*
	 * We only allow one connection to this device
	 */
	if (priv->vbus.opened) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return -EBUSY;
	}

	kobject_get(intf->dev->kobj);

	vbus_connection_init(&priv->vbus.conn, &venettap_vbus_link_ops);

	priv->vbus.opened = true;
	priv->vbus.ctx = ctx;

	vbus_memctx_get(ctx);

	spin_unlock_irqrestore(&priv->lock, flags);

	*conn = &priv->vbus.conn;

	return 0;
}

static void
venettap_intf_release(struct vbus_device_interface *intf)
{
	kobject_put(intf->dev->kobj);
}

static struct vbus_device_interface_ops venettap_device_interface_ops = {
	.connect = venettap_intf_connect,
	.release = venettap_intf_release,
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
venettap_device_bus_connect(struct vbus_device *dev, struct vbus *vbus)
{
	struct venetdev *priv = vdev_to_priv(dev);
	struct vbus_device_interface *intf = &priv->vbus.intf;

	/* We only allow one bus to connect */
	if (priv->vbus.connected)
		return -EBUSY;

	kobject_get(dev->kobj);

	intf->name = "default";
	intf->type = VENET_TYPE;
	intf->ops = &venettap_device_interface_ops;

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
venettap_device_bus_disconnect(struct vbus_device *dev, struct vbus *vbus)
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
venettap_device_release(struct vbus_device *dev)
{
	struct venetdev *priv = vdev_to_priv(dev);

	venetdev_netdev_unregister(priv);
	free_netdev(priv->netif.dev);
}


static struct vbus_device_ops venettap_device_ops = {
	.bus_connect = venettap_device_bus_connect,
	.bus_disconnect = venettap_device_bus_disconnect,
	.release = venettap_device_release,
};

#define VENETTAP_TYPE "venet-tap"

static struct attribute *attrs[] = {
	&attr_hmac.attr,
	&attr_cmac.attr,
	&attr_enabled.attr,
	&attr_burstthresh.attr,
	&attr_txmitigation.attr,
	&attr_ifname.attr,
	NULL,
};

static struct attribute_group venettap_attr_group = {
	.attrs = attrs,
};

static struct net_device_ops venettap_netdev_ops = {
	.ndo_open        = venetdev_netdev_open,
	.ndo_stop        = venetdev_netdev_stop,
	.ndo_set_config  = venetdev_netdev_config,
	.ndo_change_mtu  = venetdev_change_mtu,
	.ndo_start_xmit  = venetdev_netdev_tx,
	.ndo_do_ioctl    = venetdev_netdev_ioctl,
	.ndo_get_stats   = venetdev_netdev_stats,
};

/*
 * This is called whenever the admin instantiates our devclass via
 * "mkdir /config/vbus/devices/$(inst)/venet-tap"
 */
static int
venettap_device_create(struct vbus_devclass *dc,
		       struct vbus_device **vdev)
{
	struct net_device *dev;
	struct venetdev *priv;
	struct vbus_device *_vdev;

	dev = alloc_etherdev(sizeof(struct venetdev));
	if (!dev)
		return -ENOMEM;

	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(*priv));

	spin_lock_init(&priv->lock);
	random_ether_addr(priv->hmac);
	random_ether_addr(priv->cmac);

	/*
	 * vbus init
	 */
	_vdev = &priv->vbus.dev;

	_vdev->type            = VENETTAP_TYPE;
	_vdev->ops             = &venettap_device_ops;
	_vdev->attrs           = &venettap_attr_group;

	venetdev_init(priv, dev);

	dev->netdev_ops = &venettap_netdev_ops;

	*vdev = _vdev;

	return 0;
}

static struct vbus_devclass_ops venettap_devclass_ops = {
	.create = venettap_device_create,
};

static struct vbus_devclass venettap_devclass = {
	.name = VENETTAP_TYPE,
	.ops = &venettap_devclass_ops,
	.owner = THIS_MODULE,
};

static int __init venettap_init(void)
{
	return vbus_devclass_register(&venettap_devclass);
}

static void __exit venettap_cleanup(void)
{
	vbus_devclass_unregister(&venettap_devclass);
}

module_init(venettap_init);
module_exit(venettap_cleanup);

