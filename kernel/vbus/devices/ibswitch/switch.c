/*
 * ibswitch - A Infiniband virtual network device based on the VBUS/IOQ
 * interface
 *
 * Copyright (C) 2012 Gregory Haskins <gregory.haskins@gmail.com>
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

#include <linux/ioq.h>
#include <linux/vbus.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/ktime.h>

#include <linux/vbib.h>
#include "ibswitch.h"

MODULE_AUTHOR("Gregory Haskins");
MODULE_LICENSE("GPL");

static struct ibport *node_to_port(struct rb_node *node)
{
	return node ? container_of(node, struct ibport, node) : NULL;
}

static int port_item_compare(struct rb_node *lhs, struct rb_node *rhs)
{
	struct ibport *lport = node_to_port(lhs);
	struct ibport *rport = node_to_port(rhs);

	return lport->guid - rport->guid;
}

static int port_key_compare(const void *key, struct rb_node *node)
{
	struct ibport *port = node_to_port(node);
	long guid = *(long *)key;

	return guid - port->guid;
}

static struct map_ops port_map_ops = {
	.key_compare  = &port_key_compare,
	.item_compare = &port_item_compare,
};

/*
 * This is called whenever the admin creates a symbolic link between
 * a bus in /config/vbus/buses and our device.  It represents a bus
 * connection.  Your device can chose to allow more than one bus to
 * connect, or it can restrict it to one bus.  It can also choose to
 * register one or more device_interfaces on each bus that it
 * successfully connects to.
 */
static int
ibswitch_connect(struct vbus_device *dev, struct vbus *vbus)
{
	struct ibswitch *priv = vdev_to_priv(dev);
	struct ibport   *port;
	int              ret = -EINVAL;

	mutex_lock(&priv->lock);

	port = ibswitch_port_create(priv, vbus);
	if (!port)
		goto out;

	kobject_get(dev->kobj);

	ret = map_add(&priv->port_map, &port->node);
	BUG_ON(ret < 0);

out:
	mutex_unlock(&priv->lock);

	return ret;

}

/*
 * This is called whenever the admin removes the symbolic link between
 * a bus in /config/vbus/buses and our device.
 */
static int
ibswitch_disconnect(struct vbus_device *dev, struct vbus *vbus)
{
	struct ibswitch *priv = vdev_to_priv(dev);
	struct vbus_device_interface *intf = NULL;

	// FIXME: We need a way to translate vbus->intf

	vbus_device_interface_unregister(intf);
	kobject_put(dev->kobj);

	return 0;
}

static void
ibswitch_release(struct vbus_device *dev)
{
	struct ibswitch *priv = vdev_to_priv(dev);

	// FIXME: Do we need to free any other resources?
	kfree(priv);
}


static struct vbus_device_ops ibswitch_ops = {
	.bus_connect    = ibswitch_connect,
	.bus_disconnect = ibswitch_disconnect,
	.release        = ibswitch_release,
};

#define IBSWITCH_TYPE "ib-switch"

static struct attribute *attrs[] = {
	NULL,
};

static struct attribute_group ibswitch_attr_group = {
	.attrs = attrs,
};

/*
 * This is called whenever the admin instantiates our devclass via
 * "mkdir /config/vbus/devices/$(inst)/venet-tap"
 */
static int
ibswitch_create(struct vbus_devclass *dc, struct vbus_device **vdev)
{
	struct ibswitch *priv;
	struct vbus_device *_vdev;

	priv = kzalloc(GFP_KERNEL, sizeof(*priv));

	mutex_init(&priv->lock);
	map_init(&priv->port_map, &port_map_ops);

	/*
	 * vbus init
	 */
	_vdev = &priv->vdev;

	_vdev->type            = IBSWITCH_TYPE;
	_vdev->ops             = &ibswitch_ops;
	_vdev->attrs           = &ibswitch_attr_group;

	*vdev = _vdev;

	return 0;
}

static struct vbus_devclass_ops ibswitch_devclass_ops = {
	.create = ibswitch_create,
};

static struct vbus_devclass ibswitch_devclass = {
	.name  = IBSWITCH_TYPE,
	.ops   = &ibswitch_devclass_ops,
	.owner = THIS_MODULE,
};

static int __init ibswitch_init(void)
{
	return vbus_devclass_register(&ibswitch_devclass);
}

static void __exit ibswitch_cleanup(void)
{
	vbus_devclass_unregister(&ibswitch_devclass);
}

module_init(ibswitch_init);
module_exit(ibswitch_cleanup);

