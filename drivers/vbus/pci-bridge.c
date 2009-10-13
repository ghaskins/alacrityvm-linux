/*
 * Copyright (C) 2009 Novell.  All Rights Reserved.
 *
 * Author:
 *	Gregory Haskins <ghaskins@novell.com>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/mm.h>
#include <linux/workqueue.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/ioq.h>
#include <linux/interrupt.h>
#include <linux/vbus_driver.h>
#include <linux/vbus_pci.h>

MODULE_AUTHOR("Gregory Haskins");
MODULE_LICENSE("GPL");
MODULE_VERSION("1");

#define VBUS_PCI_NAME "pci-to-vbus-bridge"

struct vbus_pci {
	spinlock_t                lock;
	struct pci_dev           *dev;
	struct ioq                eventq;
	struct vbus_pci_event    *ring;
	struct vbus_pci_regs     *regs;
	struct vbus_pci_signals  *signals;
	int                       irq;
	int                       enabled:1;
	struct {
		struct dentry    *fs;
		int               events;
		int               qnotify;
		int               qinject;
		int               notify;
		int               inject;
		int               bridgecalls;
		int               buscalls;
	} stats;
};

static struct vbus_pci vbus_pci;

struct vbus_pci_device {
	char                     type[VBUS_MAX_DEVTYPE_LEN];
	u64                      handle;
	struct list_head         shms;
	struct vbus_device_proxy vdev;
	struct work_struct       add;
	struct work_struct       drop;
};

DEFINE_PER_CPU(struct vbus_pci_fastcall_desc, vbus_pci_percpu_fastcall)
____cacheline_aligned;

/*
 * -------------------
 * common routines
 * -------------------
 */

static int
vbus_pci_bridgecall(unsigned long nr, void *data, unsigned long len)
{
	struct vbus_pci_call_desc params = {
		.vector = nr,
		.len    = len,
		.datap  = __pa(data),
	};
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&vbus_pci.lock, flags);

	memcpy_toio(&vbus_pci.regs->bridgecall, &params, sizeof(params));
	ret = ioread32(&vbus_pci.regs->bridgecall);

	spin_unlock_irqrestore(&vbus_pci.lock, flags);

	vbus_pci.stats.bridgecalls++;

	return ret;
}

static int
vbus_pci_buscall(unsigned long nr, void *data, unsigned long len)
{
	struct vbus_pci_fastcall_desc *params;
	int ret;

	preempt_disable();

	params = &get_cpu_var(vbus_pci_percpu_fastcall);

	params->call.vector = nr;
	params->call.len    = len;
	params->call.datap  = __pa(data);

	iowrite32(smp_processor_id(), &vbus_pci.signals->fastcall);

	ret = params->result;

	preempt_enable();

	vbus_pci.stats.buscalls++;

	return ret;
}

struct vbus_pci_device *
to_dev(struct vbus_device_proxy *vdev)
{
	return container_of(vdev, struct vbus_pci_device, vdev);
}

static void
_signal_init(struct shm_signal *signal, struct shm_signal_desc *desc,
	     struct shm_signal_ops *ops)
{
	desc->magic = SHM_SIGNAL_MAGIC;
	desc->ver   = SHM_SIGNAL_VER;

	shm_signal_init(signal, shm_locality_north, ops, desc);
}

/*
 * -------------------
 * _signal
 * -------------------
 */

struct _signal {
	char               name[64];
	struct vbus_pci   *pcivbus;
	struct shm_signal  signal;
	u32                handle;
	struct rb_node     node;
	struct list_head   list;
	int                irq;
	struct irq_desc   *desc;
};

static struct _signal *
to_signal(struct shm_signal *signal)
{
       return container_of(signal, struct _signal, signal);
}

static int
_signal_inject(struct shm_signal *signal)
{
	struct _signal *_signal = to_signal(signal);

	vbus_pci.stats.inject++;
	iowrite32(_signal->handle, &vbus_pci.signals->shmsignal);

	return 0;
}

static void
_signal_release(struct shm_signal *signal)
{
	struct _signal *_signal = to_signal(signal);

	kfree(_signal);
}

static struct shm_signal_ops _signal_ops = {
	.inject  = _signal_inject,
	.release = _signal_release,
};

/*
 * -------------------
 * vbus_device_proxy routines
 * -------------------
 */

static int
vbus_pci_device_open(struct vbus_device_proxy *vdev, int version, int flags)
{
	struct vbus_pci_device *dev = to_dev(vdev);
	struct vbus_pci_deviceopen params;
	int ret;

	if (dev->handle)
		return -EINVAL;

	params.devid   = vdev->id;
	params.version = version;

	ret = vbus_pci_buscall(VBUS_PCI_HC_DEVOPEN,
				 &params, sizeof(params));
	if (ret < 0)
		return ret;

	dev->handle = params.handle;

	return 0;
}

static int
vbus_pci_device_close(struct vbus_device_proxy *vdev, int flags)
{
	struct vbus_pci_device *dev = to_dev(vdev);
	unsigned long iflags;
	int ret;

	if (!dev->handle)
		return -EINVAL;

	spin_lock_irqsave(&vbus_pci.lock, iflags);

	while (!list_empty(&dev->shms)) {
		struct _signal *_signal;

		_signal = list_first_entry(&dev->shms, struct _signal, list);

		list_del(&_signal->list);
		free_irq(_signal->irq, _signal);

		spin_unlock_irqrestore(&vbus_pci.lock, iflags);
		shm_signal_put(&_signal->signal);
		spin_lock_irqsave(&vbus_pci.lock, iflags);
	}

	spin_unlock_irqrestore(&vbus_pci.lock, iflags);

	/*
	 * The DEVICECLOSE will implicitly close all of the shm on the
	 * host-side, so there is no need to do an explicit per-shm
	 * hypercall
	 */
	ret = vbus_pci_buscall(VBUS_PCI_HC_DEVCLOSE,
				 &dev->handle, sizeof(dev->handle));

	if (ret < 0)
		printk(KERN_ERR "VBUS-PCI: Error closing device %s/%lld: %d\n",
		       vdev->type, vdev->id, ret);

	dev->handle = 0;

	return 0;
}

static void vbus_irq_chip_noop(unsigned int irq)
{
}

static struct irq_chip vbus_irq_chip = {
	.name		= "VBUS",
	.mask		= vbus_irq_chip_noop,
	.unmask		= vbus_irq_chip_noop,
	.eoi		= vbus_irq_chip_noop,
};

irqreturn_t
shm_signal_intr(int irq, void *dev)
{
	struct _signal *_signal = (struct _signal *)dev;

	_shm_signal_wakeup(&_signal->signal);

	return IRQ_HANDLED;
}

static int
vbus_pci_device_shm(struct vbus_device_proxy *vdev, const char *name,
		    int id, int prio,
		    void *ptr, size_t len,
		    struct shm_signal_desc *sdesc, struct shm_signal **signal,
		    int flags)
{
	struct vbus_pci_device *dev = to_dev(vdev);
	struct _signal *_signal = NULL;
	struct vbus_pci_deviceshm params;
	unsigned long iflags;
	int ret;

	if (!dev->handle)
		return -EINVAL;

	params.devh   = dev->handle;
	params.id     = id;
	params.flags  = flags;
	params.datap  = (u64)__pa(ptr);
	params.len    = len;

	if (signal) {
		/*
		 * The signal descriptor must be embedded within the
		 * provided ptr
		 */
		if (!sdesc
		    || (len < sizeof(*sdesc))
		    || ((void *)sdesc < ptr)
		    || ((void *)sdesc > (ptr + len - sizeof(*sdesc))))
			return -EINVAL;

		_signal = kzalloc(sizeof(*_signal), GFP_KERNEL);
		if (!_signal)
			return -ENOMEM;

		_signal_init(&_signal->signal, sdesc, &_signal_ops);

		/*
		 * take another reference for the host.  This is dropped
		 * by a SHMCLOSE event
		 */
		shm_signal_get(&_signal->signal);

		params.signal.offset = (u64)sdesc - (u64)ptr;
		params.signal.prio   = prio;
		params.signal.cookie = (u64)_signal;

	} else
		params.signal.offset = -1; /* yes, this is a u32, but its ok */

	ret = vbus_pci_buscall(VBUS_PCI_HC_DEVSHM,
				 &params, sizeof(params));
	if (ret < 0)
		goto fail;

	if (signal) {
		int irq;

		BUG_ON(ret < 0);

		_signal->handle = ret;

		irq = create_irq();
		if (irq < 0) {
			printk(KERN_ERR "Failed to create IRQ: %d\n", irq);
			ret = -ENOSPC;
			goto fail;
		}

		_signal->irq = irq;
		_signal->desc = irq_to_desc(irq);

		set_irq_chip_and_handler_name(irq,
					      &vbus_irq_chip,
					      handle_percpu_irq,
					      "edge");

		if (!name)
			snprintf(_signal->name, sizeof(_signal->name),
				"dev%lld-id%d", vdev->id, id);
		else
			snprintf(_signal->name, sizeof(_signal->name),
				"%s", name);

		ret = request_irq(irq, shm_signal_intr, 0,
				  _signal->name, _signal);
		if (ret) {
			printk(KERN_ERR "Failed to request irq: %d\n", irq);
			goto fail;
		}

		spin_lock_irqsave(&vbus_pci.lock, iflags);

		list_add_tail(&_signal->list, &dev->shms);

		spin_unlock_irqrestore(&vbus_pci.lock, iflags);

		shm_signal_get(&_signal->signal);
		*signal = &_signal->signal;
	}

	return 0;

fail:
	if (_signal) {
		/*
		 * We held two references above, so we need to drop
		 * both of them
		 */
		shm_signal_put(&_signal->signal);
		shm_signal_put(&_signal->signal);
	}

	return ret;
}

static int
vbus_pci_device_call(struct vbus_device_proxy *vdev, u32 func, void *data,
		     size_t len, int flags)
{
	struct vbus_pci_device *dev = to_dev(vdev);
	struct vbus_pci_devicecall params = {
		.devh  = dev->handle,
		.func  = func,
		.datap = (u64)__pa(data),
		.len   = len,
		.flags = flags,
	};

	if (!dev->handle)
		return -EINVAL;

	return vbus_pci_buscall(VBUS_PCI_HC_DEVCALL, &params, sizeof(params));
}

static void
vbus_pci_device_release(struct vbus_device_proxy *vdev)
{
	struct vbus_pci_device *_dev = to_dev(vdev);

	vbus_pci_device_close(vdev, 0);

	kfree(_dev);
}

struct vbus_device_proxy_ops vbus_pci_device_ops = {
	.open    = vbus_pci_device_open,
	.close   = vbus_pci_device_close,
	.shm     = vbus_pci_device_shm,
	.call    = vbus_pci_device_call,
	.release = vbus_pci_device_release,
};

/*
 * -------------------
 * vbus events
 * -------------------
 */

static void
deferred_devadd(struct work_struct *work)
{
	struct vbus_pci_device *new;
	int ret;

	new = container_of(work, struct vbus_pci_device, add);

	ret = vbus_device_proxy_register(&new->vdev);
	if (ret < 0)
		panic("failed to register device %lld(%s): %d\n",
		      new->vdev.id, new->type, ret);
}

static void
deferred_devdrop(struct work_struct *work)
{
	struct vbus_pci_device *dev;

	dev = container_of(work, struct vbus_pci_device, drop);
	vbus_device_proxy_unregister(&dev->vdev);
}

static void
event_devadd(struct vbus_pci_add_event *event)
{
	struct vbus_pci_device *new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new) {
		printk(KERN_ERR "VBUS_PCI: Out of memory on add_event\n");
		return;
	}

	INIT_LIST_HEAD(&new->shms);

	memcpy(new->type, event->type, VBUS_MAX_DEVTYPE_LEN);
	new->vdev.type        = new->type;
	new->vdev.id          = event->id;
	new->vdev.ops         = &vbus_pci_device_ops;

	dev_set_name(&new->vdev.dev, "%lld", event->id);

	INIT_WORK(&new->add, deferred_devadd);
	INIT_WORK(&new->drop, deferred_devdrop);

	schedule_work(&new->add);
}

static void
event_devdrop(struct vbus_pci_handle_event *event)
{
	struct vbus_device_proxy *dev = vbus_device_proxy_find(event->handle);

	if (!dev) {
		printk(KERN_WARNING "VBUS-PCI: devdrop failed: %lld\n",
		       event->handle);
		return;
	}

	schedule_work(&to_dev(dev)->drop);
}

static void
event_shmsignal(struct vbus_pci_handle_event *event)
{
	struct _signal *_signal = (struct _signal *)event->handle;
	struct irq_desc *desc = _signal->desc;

	vbus_pci.stats.notify++;
	desc->handle_irq(_signal->irq, desc);
}

static void
event_shmclose(struct vbus_pci_handle_event *event)
{
	struct _signal *_signal = (struct _signal *)event->handle;

	/*
	 * This reference was taken during the DEVICESHM call
	 */
	shm_signal_put(&_signal->signal);
}

/*
 * -------------------
 * eventq routines
 * -------------------
 */

static struct ioq_notifier eventq_notifier;

static int __devinit
eventq_init(int qlen)
{
	struct ioq_iterator iter;
	int ret;
	int i;

	vbus_pci.ring = kzalloc(sizeof(struct vbus_pci_event) * qlen,
				GFP_KERNEL);
	if (!vbus_pci.ring)
		return -ENOMEM;

	/*
	 * We want to iterate on the "valid" index.  By default the iterator
	 * will not "autoupdate" which means it will not hypercall the host
	 * with our changes.  This is good, because we are really just
	 * initializing stuff here anyway.  Note that you can always manually
	 * signal the host with ioq_signal() if the autoupdate feature is not
	 * used.
	 */
	ret = ioq_iter_init(&vbus_pci.eventq, &iter, ioq_idxtype_valid, 0);
	BUG_ON(ret < 0);

	/*
	 * Seek to the tail of the valid index (which should be our first
	 * item since the queue is brand-new)
	 */
	ret = ioq_iter_seek(&iter, ioq_seek_tail, 0, 0);
	BUG_ON(ret < 0);

	/*
	 * Now populate each descriptor with an empty vbus_event and mark it
	 * valid
	 */
	for (i = 0; i < qlen; i++) {
		struct vbus_pci_event *event = &vbus_pci.ring[i];
		size_t                 len   = sizeof(*event);
		struct ioq_ring_desc  *desc  = iter.desc;

		BUG_ON(iter.desc->valid);

		desc->cookie = (u64)event;
		desc->ptr    = (u64)__pa(event);
		desc->len    = len; /* total length  */
		desc->valid  = 1;

		/*
		 * This push operation will simultaneously advance the
		 * valid-tail index and increment our position in the queue
		 * by one.
		 */
		ret = ioq_iter_push(&iter, 0);
		BUG_ON(ret < 0);
	}

	vbus_pci.eventq.notifier = &eventq_notifier;

	/*
	 * And finally, ensure that we can receive notification
	 */
	ioq_notify_enable(&vbus_pci.eventq, 0);

	return 0;
}

/* Invoked whenever the hypervisor ioq_signal()s our eventq */
static void
eventq_wakeup(struct ioq_notifier *notifier)
{
	struct ioq_iterator iter;
	int ret;

	/* We want to iterate on the head of the in-use index */
	ret = ioq_iter_init(&vbus_pci.eventq, &iter, ioq_idxtype_inuse, 0);
	BUG_ON(ret < 0);

	ret = ioq_iter_seek(&iter, ioq_seek_head, 0, 0);
	BUG_ON(ret < 0);

	/*
	 * The EOM is indicated by finding a packet that is still owned by
	 * the south side.
	 *
	 * FIXME: This in theory could run indefinitely if the host keeps
	 * feeding us events since there is nothing like a NAPI budget.  We
	 * might need to address that
	 */
	while (!iter.desc->sown) {
		struct ioq_ring_desc *desc  = iter.desc;
		struct vbus_pci_event *event;

		event = (struct vbus_pci_event *)desc->cookie;

		switch (event->eventid) {
		case VBUS_PCI_EVENT_DEVADD:
			event_devadd(&event->data.add);
			break;
		case VBUS_PCI_EVENT_DEVDROP:
			event_devdrop(&event->data.handle);
			break;
		case VBUS_PCI_EVENT_SHMSIGNAL:
			event_shmsignal(&event->data.handle);
			break;
		case VBUS_PCI_EVENT_SHMCLOSE:
			event_shmclose(&event->data.handle);
			break;
		default:
			printk(KERN_WARNING "VBUS_PCI: Unexpected event %d\n",
			       event->eventid);
			break;
		};

		memset(event, 0, sizeof(*event));

		/* Advance the in-use head */
		ret = ioq_iter_pop(&iter, 0);
		BUG_ON(ret < 0);

		vbus_pci.stats.events++;
	}

	/* And let the south side know that we changed the queue */
	ioq_signal(&vbus_pci.eventq, 0);
}

static struct ioq_notifier eventq_notifier = {
	.signal = &eventq_wakeup,
};

/* Injected whenever the host issues an ioq_signal() on the eventq */
irqreturn_t
eventq_intr(int irq, void *dev)
{
	vbus_pci.stats.qnotify++;
	_shm_signal_wakeup(vbus_pci.eventq.signal);

	return IRQ_HANDLED;
}

/*
 * -------------------
 */

static int
eventq_signal_inject(struct shm_signal *signal)
{
	vbus_pci.stats.qinject++;

	/* The eventq uses the special-case handle=0 */
	iowrite32(0, &vbus_pci.signals->eventq);

	return 0;
}

static void
eventq_signal_release(struct shm_signal *signal)
{
	kfree(signal);
}

static struct shm_signal_ops eventq_signal_ops = {
	.inject  = eventq_signal_inject,
	.release = eventq_signal_release,
};

/*
 * -------------------
 */

static void
eventq_ioq_release(struct ioq *ioq)
{
	/* released as part of the vbus_pci object */
}

static struct ioq_ops eventq_ioq_ops = {
	.release = eventq_ioq_release,
};

/*
 * -------------------
 */

static void
vbus_pci_release(void)
{
#ifdef CONFIG_DEBUG_FS
	if (vbus_pci.stats.fs)
		debugfs_remove(vbus_pci.stats.fs);
#endif

	if (vbus_pci.irq > 0)
		free_irq(vbus_pci.irq, NULL);

	if (vbus_pci.signals)
		pci_iounmap(vbus_pci.dev, (void *)vbus_pci.signals);

	if (vbus_pci.regs)
		pci_iounmap(vbus_pci.dev, (void *)vbus_pci.regs);

	pci_release_regions(vbus_pci.dev);
	pci_disable_device(vbus_pci.dev);

	kfree(vbus_pci.eventq.head_desc);
	kfree(vbus_pci.ring);

	vbus_pci.enabled = false;
}

static int __devinit
vbus_pci_open(void)
{
	struct vbus_pci_bridge_negotiate params = {
		.magic        = VBUS_PCI_ABI_MAGIC,
		.version      = VBUS_PCI_HC_VERSION,
		.capabilities = 0,
	};

	return vbus_pci_bridgecall(VBUS_PCI_BRIDGE_NEGOTIATE,
				  &params, sizeof(params));
}

#define QLEN 1024

static int __devinit
vbus_pci_eventq_register(void)
{
	struct vbus_pci_busreg params = {
		.count = 1,
		.eventq = {
			{
				.count = QLEN,
				.ring  = (u64)__pa(vbus_pci.eventq.head_desc),
				.data  = (u64)__pa(vbus_pci.ring),
			},
		},
	};

	return vbus_pci_bridgecall(VBUS_PCI_BRIDGE_QREG,
				   &params, sizeof(params));
}

static int __devinit
_ioq_init(size_t ringsize, struct ioq *ioq, struct ioq_ops *ops)
{
	struct shm_signal    *signal = NULL;
	struct ioq_ring_head *head = NULL;
	size_t                len  = IOQ_HEAD_DESC_SIZE(ringsize);

	head = kzalloc(len, GFP_KERNEL | GFP_DMA);
	if (!head)
		return -ENOMEM;

	signal = kzalloc(sizeof(*signal), GFP_KERNEL);
	if (!signal) {
		kfree(head);
		return -ENOMEM;
	}

	head->magic     = IOQ_RING_MAGIC;
	head->ver	= IOQ_RING_VER;
	head->count     = ringsize;

	_signal_init(signal, &head->signal, &eventq_signal_ops);

	ioq_init(ioq, ops, ioq_locality_north, head, signal, ringsize);

	return 0;
}

#ifdef CONFIG_DEBUG_FS
static int _debugfs_seq_show(struct seq_file *m, void *p)
{
#define P(F) \
	seq_printf(m, "  .%-30s: %d\n", #F, (int)vbus_pci.stats.F)

	P(events);
	P(qnotify);
	P(qinject);
	P(notify);
	P(inject);
	P(bridgecalls);
	P(buscalls);

#undef P

	return 0;
}

static int _debugfs_fops_open(struct inode *inode, struct file *file)
{
	return single_open(file, _debugfs_seq_show, inode->i_private);
}

static const struct file_operations stat_fops = {
	.open		= _debugfs_fops_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.owner		= THIS_MODULE,
};
#endif

static int __devinit
vbus_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int ret;
	int cpu;

	if (vbus_pci.enabled)
		return -EEXIST; /* we only support one bridge per kernel */

	if (pdev->revision != VBUS_PCI_ABI_VERSION) {
		printk(KERN_DEBUG "VBUS_PCI: expected ABI version %d, got %d\n",
		       VBUS_PCI_ABI_VERSION,
		       pdev->revision);
		return -ENODEV;
	}

	vbus_pci.dev = pdev;

	ret = pci_enable_device(pdev);
	if (ret < 0)
		return ret;

	ret = pci_request_regions(pdev, VBUS_PCI_NAME);
	if (ret < 0) {
		printk(KERN_ERR "VBUS_PCI: Could not init BARs: %d\n", ret);
		goto out_fail;
	}

	vbus_pci.regs = pci_iomap(pdev, 0, sizeof(struct vbus_pci_regs));
	if (!vbus_pci.regs) {
		printk(KERN_ERR "VBUS_PCI: Could not map BARs\n");
		goto out_fail;
	}

	vbus_pci.signals = pci_iomap(pdev, 1, sizeof(struct vbus_pci_signals));
	if (!vbus_pci.signals) {
		printk(KERN_ERR "VBUS_PCI: Could not map BARs\n");
		goto out_fail;
	}

	ret = vbus_pci_open();
	if (ret < 0) {
		printk(KERN_DEBUG "VBUS_PCI: Could not register with host: %d\n",
		       ret);
		goto out_fail;
	}

	/*
	 * Allocate an IOQ to use for host-2-guest event notification
	 */
	ret = _ioq_init(QLEN, &vbus_pci.eventq, &eventq_ioq_ops);
	if (ret < 0) {
		printk(KERN_ERR "VBUS_PCI: Cound not init eventq: %d\n", ret);
		goto out_fail;
	}

	ret = eventq_init(QLEN);
	if (ret < 0) {
		printk(KERN_ERR "VBUS_PCI: Cound not setup ring: %d\n", ret);
		goto out_fail;
	}

	ret = pci_enable_msi(pdev);
	if (ret < 0) {
		printk(KERN_ERR "VBUS_PCI: Cound not enable MSI: %d\n", ret);
		goto out_fail;
	}

	vbus_pci.irq = pdev->irq;

	ret = request_irq(pdev->irq, eventq_intr, 0, "vbus", NULL);
	if (ret < 0) {
		printk(KERN_ERR "VBUS_PCI: Failed to register IRQ %d\n: %d",
		       pdev->irq, ret);
		goto out_fail;
	}

	/*
	 * Add one fastcall vector per cpu so that we can do lockless
	 * hypercalls
	 */
	for_each_possible_cpu(cpu) {
		struct vbus_pci_fastcall_desc *desc =
			&per_cpu(vbus_pci_percpu_fastcall, cpu);
		struct vbus_pci_call_desc params = {
			.vector = cpu,
			.len    = sizeof(*desc),
			.datap  = __pa(desc),
		};

		ret = vbus_pci_bridgecall(VBUS_PCI_BRIDGE_FASTCALL_ADD,
					  &params, sizeof(params));
		if (ret < 0) {
			printk(KERN_ERR \
			       "VBUS_PCI: Failed to register cpu:%d\n: %d",
			       cpu, ret);
			goto out_fail;
		}
	}

	/*
	 * Finally register our queue on the host to start receiving events
	 */
	ret = vbus_pci_eventq_register();
	if (ret < 0) {
		printk(KERN_ERR "VBUS_PCI: Could not register with host: %d\n",
		       ret);
		goto out_fail;
	}

#ifdef CONFIG_DEBUG_FS
	vbus_pci.stats.fs = debugfs_create_file(VBUS_PCI_NAME, S_IRUGO,
						NULL, NULL, &stat_fops);
	if (IS_ERR(vbus_pci.stats.fs)) {
		ret = PTR_ERR(vbus_pci.stats.fs);
		printk(KERN_ERR "VBUS_PCI: error creating stats-fs: %d\n", ret);
		goto out_fail;
	}
#endif

	vbus_pci.enabled = true;

	printk(KERN_INFO "Virtual-Bus: Copyright (c) 2009, " \
	       "Gregory Haskins <ghaskins@novell.com>\n");

	return 0;

 out_fail:
	vbus_pci_release();

	return ret;
}

static void __devexit
vbus_pci_remove(struct pci_dev *pdev)
{
	vbus_pci_release();
}

static DEFINE_PCI_DEVICE_TABLE(vbus_pci_tbl) = {
	{ PCI_DEVICE(0x11da, 0x2000) },
	{ 0 },
};

MODULE_DEVICE_TABLE(pci, vbus_pci_tbl);

static struct pci_driver vbus_pci_driver = {
	.name     = VBUS_PCI_NAME,
	.id_table = vbus_pci_tbl,
	.probe    = vbus_pci_probe,
	.remove   = vbus_pci_remove,
};

int __init
vbus_pci_init(void)
{
	memset(&vbus_pci, 0, sizeof(vbus_pci));
	spin_lock_init(&vbus_pci.lock);

	return pci_register_driver(&vbus_pci_driver);
}

static void __exit
vbus_pci_exit(void)
{
	pci_unregister_driver(&vbus_pci_driver);
}

module_init(vbus_pci_init);
module_exit(vbus_pci_exit);

