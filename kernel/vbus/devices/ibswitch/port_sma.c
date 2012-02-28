/*
 * ibswitch - A Infiniband virtual network device based on the VBUS/IOQ interface
 *
 * Copyright (C) 2012 Gregory Haskins <gregory.haskins@gmail.com>
 */

#include <rdma/ib_mad.h>
#include "ibswitch.h"

struct ib_node_info {
	u8  base_version;
	u8  class_version;
	u8  node_type;
	u8  num_ports;
	__be64 system_image_guid;
	__be64 node_guid;
	__be64 port_guid;
	__be16 partition_cap;
	__be16 device_id;
	__be32 revision;
	__be32 localport_vendorid;
} __attribute__ ((packed));

static int
nodeinfo_get(struct ibport *port, struct ib_smp *in, struct ib_smp *out)
{
	struct ib_node_info *info = (struct ib_node_info*)out->data;
	
	info->base_version                   = 1;
	info->class_version                  = 1;
	info->node_type                      = 1;
	info->num_ports                      = 1;
	info->node_guid                      = cpu_to_be64(port->guid);
	info->port_guid                      = info->node_guid;
	info->partition_cap                  = cpu_to_be16(PKEY_TABLE_LEN);
	info->device_id                      = cpu_to_be16(VBIB_DEV_ID);
	info->revision                       = 1;
	info->localport_vendorid             = 0x0030cc;

	return 0;
}

static int
portinfo_get(struct ibport *port, struct ib_smp *in, struct ib_smp *out)
{
	struct ib_port_info *info = (struct ib_port_info*)out->data;

	info->mkey                          = cpu_to_be64(port->mkey.value);
	info->gid_prefix                    = cpu_to_be64(port->gid_prefix);
	info->lid                           = cpu_to_be16(port->lid);
	info->sm_lid                        = cpu_to_be16(port->smlid);
	info->cap_mask                      = cpu_to_be32(0);
	info->diag_code                     = cpu_to_be16(0);
	info->mkey_lease_period             = cpu_to_be16(port->mkey.lease);
	info->local_port_num                = 0;
	info->link_width_enabled            = port->link_width_enabled; 
	info->link_width_supported          = IB_WIDTH_12X; 
	info->link_width_active             = IB_WIDTH_12X;
	info->linkspeed_portstate           = (7 << 4) | port->state;
	info->portphysstate_linkdown        = 
	    (port->phy_state << 4) |
	    port->link_down_default_state;
	info->mkeyprot_resv_lmc             = 
	    (port->mkey.protect_bits << 6) |
	    port->lmc;
	info->linkspeedactive_enabled       = (4 << 4) | port->link_speed_enabled;
	info->neighbormtu_mastersmsl        = (port->mtu << 4) | port->mastersmsl;
	info->vlcap_inittype                = (1 << 4) | 0;
	info->vl_high_limit                 = port->vl_high_limit;
	info->vl_arb_high_cap               = 0;
	info->vl_arb_low_cap                = 0;
	info->inittypereply_mtucap          = (port->init_type_reply << 4) | IB_MTU_4096;
	info->operationalvl_pei_peo_fpi_fpo =
	    (port->operational_vls                          << 4) |
	    ((port->partition_enforcement.inbound ? 1 : 0)  << 3) |
	    ((port->partition_enforcement.outbound ? 1 : 0) << 2) |
	    ((port->filter_raw.inbound ? 1 : 0)             << 1) |
	    ((port->filter_raw.outbound ? 1 : 0)            << 0);
	info->mkey_violations                = cpu_to_be16(port->stats.mkey_violations);
	info->pkey_violations                = cpu_to_be16(port->stats.pkey_violations);
	info->qkey_violations                = cpu_to_be16(port->stats.qkey_violations);
	info->guid_cap                       = GUID_TABLE_LEN;
	info->clientrereg_resv_subnetto      = port->subnet_timeout;
	info->resv_resptimevalue             = 0x1F;
	info->localphyerrors_overrunerrors = 
	    (port->thresholds.local_phy_errors << 4) |
	    (port->thresholds.overrun_errors << 0);
	
	return 0;
}

static int
guidinfo_get(struct ibport *port, struct ib_smp *in, struct ib_smp *out)
{
	u32 index = be32_to_cpu(in->attr_mod);
	u64 *data = out->data;
	int i;

	if (index)
		return -EINVAL;

	for (i = 0; i<GUID_TABLE_LEN; i++) {
		*data = cpu_to_be64(port->guids[i]);
		++data;
	}

	return 0;
}

int
port_sma_get(struct ibport *port, struct ib_smp *in, struct ib_smp *out)
{
    int ret = -EINVAL;

    *out = *in;
    memset(out->data, 0, sizeof(out->data));

    out->method = IB_MGMT_METHOD_GET_RESP;

    if (in->mgmt_class != IB_MGMT_CLASS_SUBN_LID_ROUTED &&
	in->mgmt_class != IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE)
	    goto out;

    if (in->method != IB_MGMT_METHOD_GET) {
	    ret = -ENOSYS;
	    goto out;
    }

    switch (in->attr_id) {
    case IB_SMP_ATTR_NODE_INFO:
	    ret = nodeinfo_get(port, in, out);
	    break;
    case IB_SMP_ATTR_PORT_INFO:
	    ret = portinfo_get(port, in, out);
	    break;
    case IB_SMP_ATTR_GUID_INFO:
	    ret = guidinfo_get(port, in, out);
	    break;
    case IB_SMP_ATTR_NOTICE:
    case IB_SMP_ATTR_NODE_DESC:
    case IB_SMP_ATTR_PKEY_TABLE:
    case IB_SMP_ATTR_SL_TO_VL_TABLE:
    case IB_SMP_ATTR_VL_ARB_TABLE:
    case IB_SMP_ATTR_SM_INFO:
    case IB_SMP_ATTR_VENDOR_DIAG:
	    break;
    }

out:
    switch (ret) {
    case -ENOSYS:
	    out->status = 2 << 2;
	    break;
    default:
	    out->status = 3 << 2;
	    break;
    }

    if (in->mgmt_class == IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE)
	    out->status |= IB_SMP_DIRECTION;
    
    return ret;
}
