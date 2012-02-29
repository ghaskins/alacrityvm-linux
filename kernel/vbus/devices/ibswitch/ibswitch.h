/*
 * ibswitch - A Infiniband virtual network device based on the VBUS/IOQ
 *            interface
 *
 * Copyright (C) 2012 Gregory Haskins <gregory.haskins@gmail.com>
 */

#ifndef _VBUS_IBSWITCH_H_
#define _VBUS_IBSWITCH_H_

#include <linux/map.h>
#include <linux/vbus.h>
#include <rdma/ib_smi.h>

#undef PDEBUG             /* undef it, just in case */
#ifdef IBSWITCH_DEBUG
#  define PDEBUG(fmt, args...) printk(KERN_DEBUG "ibswitch: " fmt, ## args)
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

#define VBIB_DEV_ID 1

struct ibswitch;

typedef u16 lid_t;

struct pkey {
	unsigned int type:1;
	unsigned int base:15;
};

#define PKEY_TABLE_LEN 32
#define GID_TABLE_LEN 32
#define GUID_TABLE_LEN 8

struct ibport {
	u64                           guid;
	struct {
		u64                   value;
		u16                   lease;
		u8                    protect_bits;
	} mkey;
	u64                           gid_prefix;
	lid_t                         lid;
	lid_t                         smlid;
	u8                            link_width_enabled;
	u8                            state;
	u8                            phy_state;
	u8                            link_down_default_state;
	u8                            lmc;
	u8                            link_speed_enabled;
	u8                            mtu;
	u8                            mastersmsl;
	u8                            vl_high_limit;
	u8                            init_type_reply;
	u8                            operational_vls;
	struct {
		bool                  inbound;
		bool                  outbound;
	} partition_enforcement;
	struct {
		bool                  inbound;
		bool                  outbound;
	} filter_raw;
	struct {
		unsigned long         mkey_violations;
		unsigned long         pkey_violations;
		unsigned long         qkey_violations;
	} stats;
	u8                            subnet_timeout;
	struct {
		u8                    local_phy_errors;
		u8                    overrun_errors;
	} thresholds;
	bool                          opened;
	struct rb_node                node;
	struct vbus                  *bus;
	struct vbus_device_interface  intf;
	struct vbus_connection        conn;
	struct vbus_memctx           *ctx;
	struct ibswitch              *ibswitch;
	struct pkey                   pkeys[PKEY_TABLE_LEN];
	u64                           guids[GUID_TABLE_LEN];
    
};

struct ibswitch {
	struct mutex       lock;
	struct map         port_map;
	struct vbus_device vdev;
	u32                hwver;
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

extern int
port_sma_get(struct ibport *port, struct ib_smp *in, struct ib_smp *out);

#endif /* _VBUS_IBSWITCH_H_ */
