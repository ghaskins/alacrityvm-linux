/*
 * ibswitch - A Infiniband virtual network device based on the VBUS/IOQ
 *            interface
 *
 * Copyright (C) 2012 Gregory Haskins <gregory.haskins@gmail.com>
 */

#ifndef _VBUS_IBSWITCH_H_
#define _VBUS_IBSWITCH_H_

#include <linux/map.h>

#undef PDEBUG             /* undef it, just in case */
#ifdef IBSWITCH_DEBUG
#  define PDEBUG(fmt, args...) printk(KERN_DEBUG "ibswitch: " fmt, ## args)
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

struct ibswitch;

struct ibport {
	long                          guid;
	bool                          opened;
	struct rb_node                node;
	struct vbus                  *bus;
	struct vbus_device_interface  intf;
	struct vbus_connection        conn;
	struct vbus_memctx           *ctx;
	struct ibswitch              *ibswitch;
};

struct ibswitch {
	struct mutex       lock;
	struct map         port_map;
	struct vbus_device vdev;
};

static inline struct ibport *intf_to_port(struct vbus_device_interface *intf)
{
	return container_of(intf, struct ibport, intf);
}

static inline struct ibport *conn_to_port(struct vbus_connection *conn)
{
	return container_of(conn, struct ibport, conn);
}

static inline struct ibswitch* vdev_to_priv(struct vbus_device *vdev)
{
	return container_of(vdev, struct ibswitch, vdev);
}

extern struct ibport*
ibswitch_port_create(struct ibswitch *ibswitch, struct vbus *vbus);

#endif /* _VBUS_IBSWITCH_H_ */
