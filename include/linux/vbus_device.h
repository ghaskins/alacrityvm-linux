/*
 * VBUS device models
 *
 * Copyright 2009 Novell.  All Rights Reserved.
 *
 * Author:
 *      Gregory Haskins <ghaskins@novell.com>
 *
 * This file deals primarily with the definitions for interfacing a virtual
 * device model to a virtual bus.  In a nutshell, a devclass begets a device,
 * which begets a device_interface, which begets a connection.
 *
 * devclass
 * -------
 *
 * To develop a vbus device, it all starts with a devclass.  You must register
 * a devclass using vbus_devclass_register().  Each registered devclass is
 * enumerated under /sys/vbus/deviceclass.
 *
 * In of itself, a devclass doesnt do much.  It is just an object factory for
 * a device whose lifetime is managed by userspace.  When userspace decides
 * it would like to create an instance of a particular devclass, the
 * devclass::create() callback is invoked (registered as part of the ops
 * structure during vbus_devclass_register()).  How and when userspace decides
 * to do this is beyond the scope of this document.  Please see:
 *
 *                         Documentation/vbus.txt
 *
 * for more details.
 *
 * device
 * -------
 *
 * A vbus device is created by a particular devclass during the invokation
 * of its devclass::create() callback.  A device is initially created without
 * any association with a bus.  One or more buses may attempt to connect to
 * a device (controlled, again, by userspace).  When this occurs, a
 * device::bus_connect() callback is invoked.
 *
 * This bus_connect() callback gives the device a chance to decide if it will
 * accept the connection, and if so, to register its interfaces.  Most devices
 * will likely only allow a connection to one bus.  Therefore, they may return
 * -EBUSY another bus is already connected.
 *
 * If the device accepts the connection, it should register one of more
 * interfaces with the bus using vbus_device_interface_register().  Most
 * devices will only support one interface, and therefore will only invoke
 * this method once.  However, some more elaborate devices may have multiple
 * functions, or abstracted topologies.  Therefore they may opt at their own
 * discretion to register more than one interface.  The interfaces do not need
 * to be uniform in type.
 *
 * device_interface
 * -------------------
 *
 * The purpose of an interface is two fold: 1) advertise a particular ABI
 * for communcation to a driver, 2) handle the initial connection of a driver.
 *
 * As such, a device_interface has a string "type" (which is akin to the
 * abi type that this interface supports, like a PCI-ID).  It also sports
 * an interface::connect() method.
 *
 * The interface::connect callback is invoked whenever a driver attempts to
 * connect to this device.  The device implements its own policy regarding
 * whether it accepts multiple connections or not.  Most devices will likely
 * only accept one connection at a time, and therefore will return -EBUSY if
 * subsequent attempts are made.
 *
 * However, if successful, the interface::connect() should return a
 * vbus_connection object
 *
 * connections
 * -----------
 *
 * A connection represents an interface that is succesfully opened.  It will
 * remain in an active state as long as the client retains the connection.
 * The connection::release() method is invoked if the client should die,
 * restart, or explicitly close the connection.  The device-model should use
 * this release() callback as the indication to clean up any resources
 * associated with a particular connection such as allocated queues, etc.
 *
 * ---
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

#ifndef _LINUX_VBUS_DEVICE_H
#define _LINUX_VBUS_DEVICE_H

#include <linux/module.h>
#include <linux/configfs.h>
#include <linux/rbtree.h>
#include <linux/shm_signal.h>
#include <linux/vbus.h>
#include <linux/kref.h>

struct vbus_device_interface;
struct vbus_connection;
struct vbus_device;
struct vbus_devclass;
struct vbus_memctx;

/*
 * ----------------------
 * devclass
 * ----------------------
 */
struct vbus_devclass_ops {
	int (*create)(struct vbus_devclass *dc,
		      struct vbus_device **dev);
	void (*release)(struct vbus_devclass *dc);
};

struct vbus_devclass {
	const char *name;
	struct vbus_devclass_ops *ops;
	struct rb_node node;
	struct kobject kobj;
	struct module *owner;
};

/**
 * vbus_devclass_register() - register a devclass with the system
 * @devclass:   The devclass context to register
 *
 * Establishes a new device-class for consumption.  Registered device-classes
 * are enumerated under /sys/vbus/deviceclass.  For more details, please see
 * Documentation/vbus*
 *
 * Returns: success = 0, <0 = ERRNO
 *
 **/
int vbus_devclass_register(struct vbus_devclass *devclass);

/**
 * vbus_devclass_unregister() - unregister a devclass with the system
 * @devclass:   The devclass context to unregister
 *
 * Removes a devclass from the system
 *
 * Returns: success = 0, <0 = ERRNO
 *
 **/
int vbus_devclass_unregister(struct vbus_devclass *devclass);

/**
 * vbus_devclass_get() - acquire a devclass context reference
 * @devclass:      devclass context
 *
 **/
static inline struct vbus_devclass *
vbus_devclass_get(struct vbus_devclass *devclass)
{
	if (!try_module_get(devclass->owner))
		return NULL;

	kobject_get(&devclass->kobj);
	return devclass;
}

/**
 * vbus_devclass_put() - release a devclass context reference
 * @devclass:      devclass context
 *
 **/
static inline void
vbus_devclass_put(struct vbus_devclass *devclass)
{
	kobject_put(&devclass->kobj);
	module_put(devclass->owner);
}

/*
 * ----------------------
 * device
 * ----------------------
 */
struct vbus_device_attribute {
	struct attribute attr;
	ssize_t (*show)(struct vbus_device *dev,
			struct vbus_device_attribute *attr,
			char *buf);
	ssize_t (*store)(struct vbus_device *dev,
			 struct vbus_device_attribute *attr,
			 const char *buf, size_t count);
};

struct vbus_device_ops {
	int (*bus_connect)(struct vbus_device *dev, struct vbus *vbus);
	int (*bus_disconnect)(struct vbus_device *dev, struct vbus *vbus);
	void (*release)(struct vbus_device *dev);
};

struct vbus_device {
	const char *type;
	struct vbus_device_ops *ops;
	struct attribute_group *attrs;
	struct kobject *kobj;
};

/*
 * ----------------------
 * device_interface
 * ----------------------
 */
struct vbus_device_interface_ops {
	int (*connect)(struct vbus_device_interface *intf,
		    struct vbus_memctx *ctx,
		    int version,
		    struct vbus_connection **conn);
	void (*release)(struct vbus_device_interface *intf);
};

struct vbus_device_interface {
	const char *name;
	const char *type;
	struct vbus_device_interface_ops *ops;
	unsigned long id;
	struct vbus_device *dev;
	struct vbus *vbus;
	struct rb_node node;
	struct kobject kobj;
};

/**
 * vbus_device_interface_register() - register an interface with a bus
 * @dev:        The device context of the caller
 * @vbus:       The bus context to register with
 * @intf:       The interface context to register
 *
 * This function is invoked (usually in the context of a device::bus_connect()
 * callback) to register a interface on a bus.  We make this an explicit
 * operation instead of implicit on the bus_connect() to facilitate devices
 * that may present multiple interfaces to a bus.  In those cases, a device
 * may invoke this function multiple times (one per supported interface).
 *
 * Returns: success = 0, <0 = ERRNO
 *
 **/
int vbus_device_interface_register(struct vbus_device *dev,
				   struct vbus *vbus,
				   struct vbus_device_interface *intf);

/**
 * vbus_device_interface_unregister() - unregister an interface with a bus
 * @intf:       The interface context to unregister
 *
 * This function is the converse of interface_register.  It is typically
 * invoked in the context of a device::bus_disconnect().
 *
 * Returns: success = 0, <0 = ERRNO
 *
 **/
int vbus_device_interface_unregister(struct vbus_device_interface *intf);

/*
 * ----------------------
 * memory context
 * ----------------------
 */
struct vbus_memctx_ops {
	unsigned long (*copy_to)(struct vbus_memctx *ctx,
				 void *dst,
				 const void *src,
				 unsigned long len);
	unsigned long (*copy_from)(struct vbus_memctx *ctx,
				   void *dst,
				   const void *src,
				   unsigned long len);
	void (*release)(struct vbus_memctx *ctx);
};

struct vbus_memctx {
	struct kref kref;
	struct vbus_memctx_ops *ops;
};

static inline void
vbus_memctx_init(struct vbus_memctx *ctx, struct vbus_memctx_ops *ops)
{
	memset(ctx, 0, sizeof(*ctx));
	kref_init(&ctx->kref);
	ctx->ops = ops;
}

#define VBUS_MEMCTX_INIT(_ops) {                                   \
        .kref = { .refcount = ATOMIC_INIT(1), },         	   \
	.ops = _ops,                                               \
}

static inline void
vbus_memctx_get(struct vbus_memctx *ctx)
{
	kref_get(&ctx->kref);
}

static inline void
_vbus_memctx_release(struct kref *kref)
{
	struct vbus_memctx *ctx = container_of(kref, struct vbus_memctx, kref);

	ctx->ops->release(ctx);
}

static inline void
vbus_memctx_put(struct vbus_memctx *ctx)
{
	kref_put(&ctx->kref, _vbus_memctx_release);
}

/*
 * ----------------------
 * memory context
 * ----------------------
 */
struct vbus_shm;

struct vbus_shm_ops {
	void (*release)(struct vbus_shm *shm);
};

struct vbus_shm {
	struct kref          kref;
	struct vbus_shm_ops *ops;
	void                *ptr;
	size_t               len;
};

static inline void
vbus_shm_init(struct vbus_shm *shm, struct vbus_shm_ops *ops,
	      void *ptr, size_t len)
{
	memset(shm, 0, sizeof(*shm));
	kref_init(&shm->kref);
	shm->ops = ops;
	shm->ptr = ptr;
	shm->len = len;
}

static inline void
vbus_shm_get(struct vbus_shm *shm)
{
	kref_get(&shm->kref);
}

static inline void
_vbus_shm_release(struct kref *kref)
{
	struct vbus_shm *shm = container_of(kref, struct vbus_shm, kref);

	shm->ops->release(shm);
}

static inline void
vbus_shm_put(struct vbus_shm *shm)
{
	kref_put(&shm->kref, _vbus_shm_release);
}

/*
 * ----------------------
 * connection
 * ----------------------
 */
struct vbus_connection_ops {
	int (*call)(struct vbus_connection *conn,
		    unsigned long func,
		    void *data,
		    unsigned long len,
		    unsigned long flags);
	int (*shm)(struct vbus_connection *conn,
		   unsigned long id,
		   struct vbus_shm *shm,
		   struct shm_signal *signal,
		   unsigned long flags);
	void (*close)(struct vbus_connection *conn);
	void (*release)(struct vbus_connection *conn);
};

struct vbus_connection {
	struct kref kref;
	struct vbus_connection_ops *ops;
};

/**
 * vbus_connection_init() - initialize a vbus_connection
 * @conn:       connection context
 * @ops:        ops structure to assign to context
 *
 **/
static inline void vbus_connection_init(struct vbus_connection *conn,
					struct vbus_connection_ops *ops)
{
	memset(conn, 0, sizeof(*conn));
	kref_init(&conn->kref);
	conn->ops = ops;
}

/**
 * vbus_connection_get() - acquire a connection context reference
 * @conn:       connection context
 *
 **/
static inline void vbus_connection_get(struct vbus_connection *conn)
{
	kref_get(&conn->kref);
}

static inline void _vbus_connection_release(struct kref *kref)
{
	struct vbus_connection *conn;

	conn = container_of(kref, struct vbus_connection, kref);
	conn->ops->release(conn);
}

/**
 * vbus_connection_put() - release a connection context reference
 * @conn:       connection context
 *
 **/
static inline void vbus_connection_put(struct vbus_connection *conn)
{
	kref_put(&conn->kref, _vbus_connection_release);
}

#endif /* _LINUX_VBUS_DEVICE_H */
