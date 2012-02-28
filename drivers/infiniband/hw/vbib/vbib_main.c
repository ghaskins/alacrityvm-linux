/*
 * vbib - A virtualized Infiniband HCA based on the VBUS interface
 *
 * Copyright (C) 2012 Gregory Haskins <gregory.haskins@gmail.com>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/ioq.h>
#include <linux/vbus_driver.h>
#include <linux/vbib.h>

#include <rdma/ib_smi.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>

MODULE_AUTHOR("Gregory Haskins");
MODULE_DESCRIPTION("VBUS InfiniBand HCA low-level driver");
MODULE_LICENSE("GPL");
MODULE_VERSION("1");

struct vbib_priv {
	struct ib_device           ibdev; /* must be first */
	struct vbus_device_proxy  *vdev;
	struct {
		long gid_table_len;
		long pkey_table_len;
	} limits;
};

static struct vbib_priv*
ibdev_to_priv(struct ib_device *ibdev)
{
	return container_of(ibdev, struct vbib_priv, ibdev);
}

static int
devcall(struct vbib_priv *priv, u32 func, void *data, size_t len)
{
	struct vbus_device_proxy *dev = priv->vdev;

	return dev->ops->call(dev, func, data, len, 0);
}

static int
getattr(struct vbib_priv *priv, u32 attr, void *data, size_t len)
{
	struct vbib_attr _data = {attr, len, (u64)__pa(data)};

	return devcall(priv, VBIB_FUNC_GET_ATTR,  &_data, sizeof(_data));
}

static int
query_local_smi(struct vbib_priv *priv, struct ib_smp *data)
{
	return devcall(priv, VBIB_FUNC_QUERY_LOCAL_SMI,  &data, sizeof(data));
}

static void
init_query_smp(struct ib_smp *data)
{
	memset(data, 0, sizeof(*data));
	data->base_version  = 1;
	data->mgmt_class    = IB_MGMT_CLASS_SUBN_LID_ROUTED;
	data->class_version = 1;
	data->method        = IB_MGMT_METHOD_GET;
}

static int
vbib_query_device(struct ib_device *ibdev, struct ib_device_attr *props)
{
	struct vbib_priv *priv = ibdev_to_priv(ibdev);
	struct ib_smp smp;
	int ret;

	init_query_smp(&smp);
	smp.attr_id = IB_SMP_ATTR_NODE_INFO;

	ret = query_local_smi(priv, &smp);
	if (ret)
		return ret;

	memset(props, 0, sizeof *props);

	props->device_cap_flags    = 0;
	props->vendor_id           = be32_to_cpup((__be32 *) (smp.data + 36)) &
		0xffffff;
	props->vendor_part_id      = be16_to_cpup((__be16 *) (smp.data + 30));
	props->hw_ver              = be32_to_cpup((__be32 *) (smp.data + 32));

	props->max_mr_size         = ~0ull;
	props->page_size_cap       = 4 * 1024 * 1024;
	props->max_qp              = 1024;
	props->max_qp_wr           = 1024;
	props->max_sge             = 1024;
	props->max_cq              = 1024;
	props->max_cqe             = 1024;
	props->max_mr              = 1024;
	props->atomic_cap          = IB_ATOMIC_HCA;
	props->max_pkeys           = 1024;

	return 0;
}

static int
vbib_query_port(struct ib_device *ibdev, u8 port, struct ib_port_attr *props)
{
	struct vbib_priv *priv = ibdev_to_priv(ibdev);
	struct ib_smp smp;
	int ret;

	init_query_smp(&smp);
	smp.attr_id  = IB_SMP_ATTR_PORT_INFO;
	smp.attr_mod = cpu_to_be32(port);

	ret = query_local_smi(priv, &smp);
	if (ret)
		return ret;

	memset(props, 0, sizeof *props);

	props->lid               = be16_to_cpup((__be16 *) (smp.data + 16));
	props->lmc               = smp.data[34] & 0x7;
	props->sm_lid            = be16_to_cpup((__be16 *) (smp.data + 18));
	props->sm_sl             = smp.data[36] & 0xf;
	props->state             = smp.data[32] & 0xf;
	props->phys_state        = smp.data[33] >> 4;
	props->port_cap_flags    = be32_to_cpup((__be32 *) (smp.data + 20));
	props->gid_tbl_len       = priv->limits.gid_table_len;
	props->max_msg_sz        = 0x80000000;
	props->pkey_tbl_len      = priv->limits.pkey_table_len;
	props->bad_pkey_cntr     = be16_to_cpup((__be16 *) (smp.data + 46));
	props->qkey_viol_cntr    = be16_to_cpup((__be16 *) (smp.data + 48));
	props->active_width      = smp.data[31] & 0xf;
	props->active_speed      = smp.data[35] >> 4;
	props->max_mtu           = smp.data[41] & 0xf;
	props->active_mtu        = smp.data[36] >> 4;
	props->subnet_timeout    = smp.data[51] & 0x1f;
	props->max_vl_num        = smp.data[37] >> 4;
	props->init_type_reply   = smp.data[41] >> 4;

	return 0;
}

static int
vbib_query_pkey(struct ib_device *ibdev,
		 u8 port, u16 index, u16 *pkey)
{
	struct vbib_priv *priv = ibdev_to_priv(ibdev);
	struct ib_smp smp;
	int ret;

	init_query_smp(&smp);
	smp.attr_id  = IB_SMP_ATTR_PKEY_TABLE;
	smp.attr_mod = cpu_to_be32(index / 32);

	ret = query_local_smi(priv, &smp);
	if (ret)
		return ret;

	*pkey = be16_to_cpu(((__be16 *) smp.data)[index % 32]);

	return 0;
}

static int
vbib_query_gid(struct ib_device *ibdev, u8 port, int index, union ib_gid *gid)
{
	struct vbib_priv *priv = ibdev_to_priv(ibdev);
	struct ib_smp smp;
	int ret;

	init_query_smp(&smp);
	smp.attr_id  = IB_SMP_ATTR_PORT_INFO;
	smp.attr_mod = cpu_to_be32(port);

	ret = query_local_smi(priv, &smp);
	if (ret)
		return ret;

	memcpy(gid->raw, smp.data + 8, 8);

	init_query_smp(&smp);
	smp.attr_id  = IB_SMP_ATTR_GUID_INFO;
	smp.attr_mod = cpu_to_be32(index / 8);

	ret = query_local_smi(priv, &smp);
	if (ret)
		return ret;

	memcpy(gid->raw + 8, smp.data + (index % 8) * 8, 8);

	return 0;
}

/*
 * This is called whenever a new vbus_device_proxy is added to the vbus
 * with the matching VBIB_TYPE
 */
static int
vbib_probe(struct vbus_device_proxy *vdev)
{
	struct vbib_priv  *priv = NULL;
	int                ret;

	printk(KERN_INFO "VBIB: Found new device at %lld\n", vdev->id);

	ret = vdev->ops->open(vdev, VBIB_HCA_ABI_VERSION, 0);
	if (ret < 0)
		return ret;

	priv = (struct vbib_priv *) ib_alloc_device(sizeof *priv);
	if (!priv) {
		dev_err(&vdev->dev, "Device struct alloc failed, aborting.\n");
		ret = -ENOMEM;
		goto err;
	}

	priv->vdev = vdev;

	strlcpy(priv->ibdev.name, "vbib%d", IB_DEVICE_NAME_MAX);
	priv->ibdev.owner                = THIS_MODULE;

#define GET(T, D)                              \
	ret = getattr(priv, T, &D, sizeof(D)); \
	if (ret < 0)                           \
		return ret;
	
	GET(VBIB_ATTR_GID_TABLE_LEN,  priv->limits.gid_table_len);
	GET(VBIB_ATTR_PKEY_TABLE_LEN, priv->limits.pkey_table_len);

#undef GET

	priv->ibdev.uverbs_abi_ver	 = VBIB_UVERBS_ABI_VERSION;
	priv->ibdev.uverbs_cmd_mask	 = 0;

#if 0
		(1ull << IB_USER_VERBS_CMD_GET_CONTEXT)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_DEVICE)	|
		(1ull << IB_USER_VERBS_CMD_QUERY_PORT)		|
		(1ull << IB_USER_VERBS_CMD_ALLOC_PD)		|
		(1ull << IB_USER_VERBS_CMD_DEALLOC_PD)		|
		(1ull << IB_USER_VERBS_CMD_REG_MR)		|
		(1ull << IB_USER_VERBS_CMD_DEREG_MR)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL)	|
		(1ull << IB_USER_VERBS_CMD_CREATE_CQ)		|
		(1ull << IB_USER_VERBS_CMD_RESIZE_CQ)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_CQ)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_QP)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_QP)		|
		(1ull << IB_USER_VERBS_CMD_MODIFY_QP)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_QP)		|
		(1ull << IB_USER_VERBS_CMD_ATTACH_MCAST)	|
		(1ull << IB_USER_VERBS_CMD_DETACH_MCAST);
#endif

	priv->ibdev.node_type            = RDMA_NODE_IB_CA;
	priv->ibdev.phys_port_cnt        = 1;
	priv->ibdev.num_comp_vectors     = 1;
	priv->ibdev.dma_device           = &vdev->dev;
	priv->ibdev.query_device         = vbib_query_device;
	priv->ibdev.query_port           = vbib_query_port;
	priv->ibdev.query_pkey           = vbib_query_pkey;
	priv->ibdev.query_gid            = vbib_query_gid;

#if 0
	priv->ibdev.modify_device        = vbib_modify_device;
	priv->ibdev.modify_port          = vbib_modify_port;
	priv->ibdev.alloc_ucontext       = vbib_alloc_ucontext;
	priv->ibdev.dealloc_ucontext     = vbib_dealloc_ucontext;
	priv->ibdev.mmap                 = vbib_mmap_uar;
	priv->ibdev.alloc_pd             = vbib_alloc_pd;
	priv->ibdev.dealloc_pd           = vbib_dealloc_pd;
	priv->ibdev.create_ah            = vbib_ah_create;
	priv->ibdev.query_ah             = vbib_ah_query;
	priv->ibdev.destroy_ah           = vbib_ah_destroy;
	priv->ibdev.create_qp            = vbib_create_qp;
	priv->ibdev.modify_qp            = vbib_modify_qp;
	priv->ibdev.query_qp             = vbib_query_qp;
	priv->ibdev.destroy_qp           = vbib_destroy_qp;
	priv->ibdev.create_cq            = vbib_create_cq;
	priv->ibdev.resize_cq            = vbib_resize_cq;
	priv->ibdev.destroy_cq           = vbib_destroy_cq;
	priv->ibdev.poll_cq              = vbib_poll_cq;
	priv->ibdev.get_dma_mr           = vbib_get_dma_mr;
	priv->ibdev.reg_phys_mr          = vbib_reg_phys_mr;
	priv->ibdev.reg_user_mr          = vbib_reg_user_mr;
	priv->ibdev.dereg_mr             = vbib_dereg_mr;
	priv->ibdev.attach_mcast         = vbib_multicast_attach;
	priv->ibdev.detach_mcast         = vbib_multicast_detach;
	priv->ibdev.process_mad          = vbib_process_mad;
	priv->ibdev.req_notify_cq        = vbib_arm_cq;
	priv->ibdev.post_send            = vbib_post_send;
	priv->ibdev.post_recv            = vbib_post_receive;
#endif
	
	ret = ib_register_device(&priv->ibdev, NULL);
	if (ret)
		goto err;

	return ret;

err:
	if (priv)
		ib_dealloc_device(&priv->ibdev);

	vdev->ops->close(vdev, 0);

	return ret;
}

static int
vbib_remove(struct vbus_device_proxy *vdev)
{
	struct vbib_priv *priv = vdev->priv;

	ib_unregister_device(&priv->ibdev);
	ib_dealloc_device(&priv->ibdev);

	vdev->ops->close(vdev, 0);

	return 0;
}

static struct vbus_driver_ops vbib_driver_ops = {
	.probe  = vbib_probe,
	.remove = vbib_remove,
};

static struct vbus_driver vbib_driver = {
	.type   = VBIB_TYPE,
	.owner  = THIS_MODULE,
	.ops    = &vbib_driver_ops,
};

static __init int
vbib_init_module(void)
{
	printk(KERN_INFO "Virtual-Bus Infiniband: Copyright (C) 2012 Gregory Haskins\n");
	return vbus_driver_register(&vbib_driver);
}

static __exit void
vbib_cleanup(void)
{
	vbus_driver_unregister(&vbib_driver);
}

module_init(vbib_init_module);
module_exit(vbib_cleanup);

VBUS_DRIVER_AUTOPROBE(VBIB_TYPE);
