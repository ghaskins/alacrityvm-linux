/*
 * ibswitch - A Infiniband virtual network device based on the VBUS/IOQ interface
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
ibswitch_hca_call_negcap(struct ibport *port, void *data, unsigned long len)
{
	struct vbus_memctx *ctx = port->ctx;
	struct vbib_capabilities caps;
	int ret;

	if (len != sizeof(caps))
		return -EINVAL;

	ret = ctx->ops->copy_from(ctx, &caps, data, sizeof(caps));
	if (ret)
		return -EFAULT;

	switch (caps.gid) {
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
 * This is called whenever a driver wants to perform a synchronous
 * "function call" to our device.  It is similar to the notion of
 * an ioctl().  The parameters are part of the ABI between the device
 * and driver.
 */
int
ibswitch_hca_call(struct vbus_connection *conn,
		    unsigned long func,
		    void *data,
		    unsigned long len,
		    unsigned long flags)
{
	struct ibport *port = conn_to_port(conn);

	PDEBUG("call -> %d with %p/%d\n", func, data, len);

	switch (func) {
	    case VBIB_FUNC_NEGCAP:
		return ibswitch_hca_call_negcap(port, data, len);
	default:
		return -EINVAL;
	}
}

/*
 * This is called whenever a driver wants to open a new IOQ between itself
 * and our device.  The "id" namespace is managed by the device
 * and should be understood by the driver as part of its ABI agreement.
 *
 * The device should take a reference to the IOQ via ioq_get() and hold it
 * until the connection is released.
 */
int
ibswitch_hca_shm(struct vbus_connection *conn,
		 unsigned long id,
		 struct vbus_shm *shm,
		 struct shm_signal *signal,
		 unsigned long flags)
{
	struct ibport *port = conn_to_port(conn);

	PDEBUG("queue -> %p/%d attached\n", shm, id);

	switch (id) {
	default:
		return -EINVAL;
	}

	return 0;
}

void
ibswitch_hca_close(struct vbus_connection *conn)
{
	struct ibport *port = conn_to_port(conn);

	port->opened = false;
}

/*
 * This is called whenever the driver closes all references to our device
 */
void
ibswitch_hca_release(struct vbus_connection *conn)
{
	struct ibport *port = conn_to_port(conn);

	PDEBUG("connection released\n");

	vbus_memctx_put(port->ctx);
	kobject_put(port->intf.dev->kobj);
}

static struct vbus_connection_ops ibswitch_hca_ops = {
	.call    = ibswitch_hca_call,
	.shm     = ibswitch_hca_shm,
	.close   = ibswitch_hca_close,
	.release = ibswitch_hca_release,
};

/*
 * This is called whenever a driver wants to open our device_interface
 * for communication.
 */
static int
ibswitch_port_open(struct vbus_device_interface *intf,
		   struct vbus_memctx *ctx,
		   int version,
		   struct vbus_connection **conn)
{
	struct ibport *port = intf_to_port(intf);
	unsigned long flags;

	PDEBUG("connect\n");

	if (version != VBIB_HCA_ABI_VERSION)
		return -EINVAL;

	/*
	 * We only allow one connection to this device
	 */
	if (port->opened)
		return -EBUSY;

	kobject_get(intf->dev->kobj);

	vbus_connection_init(&port->conn, &ibswitch_hca_ops);

	port->opened = true;
	port->ctx = ctx;

	vbus_memctx_get(ctx);

	*conn = &port->conn;

	return 0;
}

static void
ibswitch_port_release(struct vbus_device_interface *intf)
{
	kobject_put(intf->dev->kobj);
}

static struct vbus_device_interface_ops ibswitch_interface_ops = {
	.connect = ibswitch_port_open,
	.release = ibswitch_port_release,
};

struct ibport*
ibswitch_port_create(struct ibswitch *ibswitch, struct vbus *vbus)
{
	struct ibport                *port;
	struct vbus_device_interface *intf;
	int ret;

	port = kzalloc(GFP_KERNEL, sizeof(*port));
	if (!port)
		return NULL;
	
	port->bus      = vbus;
	port->ibswitch = ibswitch;

	intf = &port->intf;
	
	intf->name = "vbib-hca";
	intf->type = VBIB_TYPE;
	intf->ops = &ibswitch_interface_ops;

	ret = vbus_device_interface_register(&port->ibswitch->vdev,
					     vbus, intf);
	if (ret < 0)
		goto err;

	return port;

err:
	kfree(port);

	return NULL;
		
}
