#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/kvm_host.h>
#include <linux/kvm_xinterface.h>
#include <linux/shm_signal_eventfd.h>
#include <linux/eventfd.h>

#include <linux/vbus.h>
#include <linux/vbus_kvm.h>
#include <linux/vbus_client.h>

MODULE_AUTHOR("Gregory Haskins");
MODULE_LICENSE("GPL");

struct vbus_kvm;

#define EVENTQ_COUNT 8

struct _eventq {
	spinlock_t          lock;
	int                 prio;
	struct ioq         *ioq;
	struct ioq_notifier notifier;
	struct vbus_shm    *shm;
	struct shm_signal   signal;
	struct eventfd_ctx *eventfd;
	struct list_head    backlog;
	struct {
		u64               gpa;
		struct kvm_xvmap *xvmap;
	} ringdata;
	struct work_struct  wakeup;
	bool                backpressure;
};

enum _state {
       _state_init,
       _state_open,
       _state_connect,
       _state_ready,
};

struct _fastcall_channel {
	unsigned int                   id;
	struct list_head               list;
	struct vbus_shm               *shm;
	struct vbus_pci_fastcall_desc *desc;
};

struct vbus_kvm {
	struct kref             kref;
	struct mutex	        lock;
	struct srcu_struct      srcu;
	struct kvm_xinterface  *kvm;
	struct kvm_xioevent    *shmsignals;
	struct {
		struct kvm_xioevent   *ioevent;
		struct {
			struct radix_tree_root radix;
			struct list_head       list;
		} channels;
	} fastcalls;
	enum _state             state;
	struct vbus            *vbus;
	struct vbus_client     *client;
	struct vbus_memctx     *ctx;
	struct mm_struct       *mm;
	struct {
		int             count;
		struct _eventq  queues[EVENTQ_COUNT];
	} eventq;
	struct notifier_block   vbusnotify;
};

static inline struct vbus_kvm *
vbus_kvm_get(struct vbus_kvm *vkvm)
{
	kref_get(&vkvm->kref);

	return vkvm;
}

static inline void
_vbus_kvm_release(struct kref *kref)
{
	struct vbus_kvm *vkvm = container_of(kref, struct vbus_kvm, kref);

	if (vkvm->kvm)
		kvm_xinterface_put(vkvm->kvm);

	synchronize_srcu(&vkvm->srcu);
	cleanup_srcu_struct(&vkvm->srcu);

	kfree(vkvm);
}

static inline void
vbus_kvm_put(struct vbus_kvm *vkvm)
{
	kref_put(&vkvm->kref, _vbus_kvm_release);
}

/*
 * -----------------
 * _shm routines
 * -----------------
 */

struct _shm {
	struct kvm_xvmap  *xvmap;
	struct vbus_shm    shm;
};

static void
_shm_release(struct vbus_shm *shm)
{
	struct _shm *_shm = container_of(shm, struct _shm, shm);

	kvm_xvmap_put(_shm->xvmap);
	kfree(_shm);
}

static struct vbus_shm_ops _shm_ops = {
	.release = _shm_release,
};

static struct _shm *
_shm_map(struct vbus_kvm *vkvm, __u64 ptr, __u32 len)
{
	struct _shm           *_shm;
	struct kvm_xinterface *kvm = vkvm->kvm;

	if (!can_do_mlock())
		return ERR_PTR(-EPERM);

	_shm = kzalloc(sizeof(*_shm), GFP_KERNEL);
	if (!_shm)
		return ERR_PTR(-ENOMEM);

	_shm->xvmap = kvm->ops->vmap(kvm, ptr, len);
	if (IS_ERR(_shm->xvmap)) {
		int ret = PTR_ERR(_shm->xvmap);
		kfree(_shm);
		return ERR_PTR(ret);
	}

	vbus_shm_init(&_shm->shm, &_shm_ops, _shm->xvmap->addr, len);

	return _shm;
}

/*
 * -----------------
 * vbus_memctx routines
 * -----------------
 */

struct _memctx {
	struct vbus_kvm    *vkvm;
	struct vbus_memctx  ctx;
};

static struct _memctx *to_memctx(struct vbus_memctx *ctx)
{
	return container_of(ctx, struct _memctx, ctx);
}


static unsigned long
_memctx_copy_to(struct vbus_memctx *ctx, void *dst, const void *src,
	       unsigned long n)
{
	struct _memctx *_memctx = to_memctx(ctx);
	struct kvm_xinterface *kvm = _memctx->vkvm->kvm;

	return kvm->ops->copy_to(kvm, (unsigned long)dst, src, n);
}

static unsigned long
_memctx_copy_from(struct vbus_memctx *ctx, void *dst, const void *src,
		  unsigned long n)
{
	struct _memctx *_memctx = to_memctx(ctx);
	struct kvm_xinterface *kvm = _memctx->vkvm->kvm;

	return kvm->ops->copy_from(kvm, dst, (unsigned long)src, n);
}

static struct mm_struct *
_memctx_mm_get(struct vbus_memctx *ctx)
{
	struct _memctx *_memctx = to_memctx(ctx);
	struct mm_struct *mm = _memctx->vkvm->mm;

	atomic_inc(&mm->mm_users);

	return mm;
}

static unsigned long
_memctx_sg_map(struct vbus_memctx *ctx, struct scatterlist *sgl, int nelems)
{
	struct _memctx *_memctx = to_memctx(ctx);
	struct kvm_xinterface *kvm = _memctx->vkvm->kvm;

	return kvm->ops->sgmap(kvm, sgl, nelems, 0);
}

static void
_memctx_release(struct vbus_memctx *ctx)
{
	struct _memctx *_memctx = to_memctx(ctx);

	vbus_kvm_put(_memctx->vkvm);
	kfree(_memctx);
}

static struct vbus_memctx_ops _memctx_ops = {
	.copy_to   = &_memctx_copy_to,
	.copy_from = &_memctx_copy_from,
	.mm_get    = &_memctx_mm_get,
	.sg_map    = &_memctx_sg_map,
	.release   = &_memctx_release,
};

static struct vbus_memctx *_memctx_alloc(struct vbus_kvm *vkvm)
{
	struct _memctx *_memctx;

	_memctx = kzalloc(sizeof(*_memctx), GFP_KERNEL);
	if (!_memctx)
		return NULL;

	vbus_kvm_get(vkvm);
	_memctx->vkvm = vkvm;

	vbus_memctx_init(&_memctx->ctx, &_memctx_ops);

	return &_memctx->ctx;
}

/*
 * -----------------
 * general routines
 * -----------------
 */

static int
_signal_init(struct shm_signal_desc *desc, struct shm_signal *signal,
	     struct shm_signal_ops *ops)
{
	if (desc->magic != SHM_SIGNAL_MAGIC)
		return -EINVAL;

	if (desc->ver != SHM_SIGNAL_VER)
		return -EINVAL;

	shm_signal_init(signal, shm_locality_south, ops, desc);

	return 0;
}

static struct vbus_pci_event *
event_ptr_translate(struct _eventq *eventq, u64 ptr)
{
	u64 off = ptr - eventq->ringdata.gpa;

	if ((ptr < eventq->ringdata.gpa)
	    || (off > (eventq->ringdata.xvmap->len - sizeof(struct vbus_pci_event))))
		return NULL;

	return eventq->ringdata.xvmap->addr + off;
}

/*
 * ------------------
 * event-object code
 * ------------------
 */

struct _event {
	struct kref           kref;
	struct list_head      list;
	struct vbus_pci_event data;
};

static void
_event_init(struct _event *event)
{
	memset(event, 0, sizeof(*event));
	kref_init(&event->kref);
	INIT_LIST_HEAD(&event->list);
}

static void
_event_get(struct _event *event)
{
	kref_get(&event->kref);
}

static inline void
_event_release(struct kref *kref)
{
	struct _event *event = container_of(kref, struct _event, kref);

	kfree(event);
}

static inline void
_event_put(struct _event *event)
{
	kref_put(&event->kref, _event_release);
}

/*
 * ------------------
 * event-inject code
 * ------------------
 */

static struct _eventq *notify_to_eventq(struct ioq_notifier *notifier)
{
	return container_of(notifier, struct _eventq, notifier);
}

static struct _eventq *signal_to_eventq(struct shm_signal *signal)
{
	return container_of(signal, struct _eventq, signal);
}

static struct vbus_kvm *eventq_to_bus(struct _eventq *eventq)
{
	return container_of(eventq, struct vbus_kvm,
			    eventq.queues[eventq->prio]);
}

/*
 * This is invoked by the guest whenever they signal our eventq when
 * we have notifications enabled
 */
static void
eventq_notify(struct ioq_notifier *notifier)
{
	struct _eventq *eventq = notify_to_eventq(notifier);
	unsigned long           flags;

	spin_lock_irqsave(&eventq->lock, flags);

	if (eventq->ioq && !ioq_full(eventq->ioq, ioq_idxtype_inuse)) {
		eventq->backpressure = false;
		ioq_notify_disable(eventq->ioq, 0);
		schedule_work(&eventq->wakeup);
	}

	spin_unlock_irqrestore(&eventq->lock, flags);
}

static void
events_flush(struct _eventq *eventq)
{
	struct ioq_iterator     iter;
	int                     ret;
	unsigned long           flags;
	struct _event          *_event, *tmp;
	int                     dirty = 0;
	struct ioq             *ioq = NULL;

	spin_lock_irqsave(&eventq->lock, flags);

	if (!eventq->ioq) {
		spin_unlock_irqrestore(&eventq->lock, flags);
		return;
	}

	/* We want to iterate on the tail of the in-use index */
	ret = ioq_iter_init(eventq->ioq, &iter, ioq_idxtype_inuse, 0);
	BUG_ON(ret < 0);

	ret = ioq_iter_seek(&iter, ioq_seek_tail, 0, 0);
	BUG_ON(ret < 0);

	list_for_each_entry_safe(_event, tmp, &eventq->backlog, list) {
		struct vbus_pci_event *ev;

		if (!iter.desc->sown) {
			eventq->backpressure = true;
			ioq_notify_enable(eventq->ioq, 0);
			break;
		}

		if (iter.desc->len < sizeof(*ev)) {
			SHM_SIGNAL_FAULT(eventq->ioq->signal,
					 "Desc too small on eventq: " \
					 "%p: %ld<%zu",
					 (void *)iter.desc->ptr,
					 (unsigned long)iter.desc->len,
					 sizeof(*ev));
			break;
		}

		ev = event_ptr_translate(eventq, iter.desc->ptr);
		if (!ev) {
			SHM_SIGNAL_FAULT(eventq->ioq->signal,
					 "Invalid address on eventq: %p",
					 (void *)iter.desc->ptr);
			break;
		}

		memcpy(ev, &_event->data, sizeof(*ev));

		list_del_init(&_event->list);
		_event_put(_event);

		ret = ioq_iter_push(&iter, 0);
		BUG_ON(ret < 0);

		dirty = 1;
	}

	if (dirty)
		ioq = ioq_get(eventq->ioq);

	spin_unlock_irqrestore(&eventq->lock, flags);

	/*
	 * Signal the IOQ outside of the spinlock so that we can potentially
	 * directly inject this interrupt instead of deferring it
	 */
	if (ioq) {
		ioq_signal(ioq, 0);
		ioq_put(ioq);
	}
}

static int
event_inject(struct _eventq *eventq, struct _event *_event)
{
	unsigned long flags;

	if (!list_empty(&_event->list))
		return -EBUSY;

	spin_lock_irqsave(&eventq->lock, flags);
	list_add_tail(&_event->list, &eventq->backlog);
	spin_unlock_irqrestore(&eventq->lock, flags);

	events_flush(eventq);

	return 0;
}

static void
eventq_reinject(struct work_struct *work)
{
	struct _eventq *eventq;

	eventq = container_of(work, struct _eventq, wakeup);

	events_flush(eventq);
}

/*
 * devadd/drop are in the slow path and are rare enough that we will
 * simply allocate memory for the event from the heap
 */
static int
devadd_inject(struct _eventq *eventq, const char *type, u64 id)
{
	struct _event *_event;
	struct vbus_pci_add_event *ae;
	int ret;

	_event = kmalloc(sizeof(*_event), GFP_KERNEL);
	if (!_event)
		return -ENOMEM;

	_event_init(_event);

	_event->data.eventid = VBUS_PCI_EVENT_DEVADD;
	ae = (struct vbus_pci_add_event *)&_event->data.data;
	ae->id = id;
	strncpy(ae->type, type, VBUS_MAX_DEVTYPE_LEN);

	ret = event_inject(eventq, _event);
	if (ret < 0)
		_event_put(_event);

	return ret;
}

/*
 * "handle" events are used to send any kind of event that simply
 * uses a handle as a parameter.  This includes things like DEVDROP
 * and SHMSIGNAL, etc.
 */
static struct _event *
handle_event_alloc(u64 id, u64 handle)
{
	struct _event *_event;
	struct vbus_pci_handle_event *he;

	_event = kmalloc(sizeof(*_event), GFP_KERNEL);
	if (!_event)
		return NULL;

	_event_init(_event);
	_event->data.eventid = id;

	he = (struct vbus_pci_handle_event *)&_event->data.data;
	he->handle = handle;

	return _event;
}

static int
devdrop_inject(struct _eventq *eventq, u64 id)
{
	struct _event *_event;
	int ret;

	_event = handle_event_alloc(VBUS_PCI_EVENT_DEVDROP, id);
	if (!_event)
		return -ENOMEM;

	ret = event_inject(eventq, _event);
	if (ret < 0)
		_event_put(_event);

	return ret;
}

static struct _eventq *
prio_to_eventq(struct vbus_kvm *vkvm, int prio)
{
	int real_prio = min(prio, vkvm->eventq.count-1);

	return &vkvm->eventq.queues[real_prio];
}

/*
 * -----------------
 * event ioq
 *
 * This queue is used by the infrastructure to transmit events (such as
 * "new device", or "signal an ioq") to the guest.  We do this so that
 * we minimize the number of hypercalls required to inject an event.
 * In theory, the guest only needs to process a single interrupt vector
 * and it doesnt require switching back to host context since the state
 * is placed within the ring
 * -----------------
 */

static int
eventq_signal_inject(struct shm_signal *signal)
{
	struct _eventq *eventq = signal_to_eventq(signal);

	eventfd_signal(eventq->eventfd, 1);

	return 0;
}

static void
eventq_signal_release(struct shm_signal *signal)
{
	struct _eventq *eventq = signal_to_eventq(signal);
	struct vbus_kvm        *vkvm  = eventq_to_bus(eventq);

	flush_work(&eventq->wakeup);

	eventfd_ctx_put(eventq->eventfd);
	vbus_shm_put(eventq->shm);
	eventq->shm = NULL;

	if (eventq->ringdata.xvmap)
		kvm_xvmap_put(eventq->ringdata.xvmap);

	vbus_kvm_put(vkvm);
}

static struct shm_signal_ops eventq_signal_ops = {
	.inject  = eventq_signal_inject,
	.release = eventq_signal_release,
};

/*
 * -----------------
 * device_signal routines
 *
 * This is the more standard signal that is allocated to communicate
 * with a specific device's shm region
 * -----------------
 */

struct device_signal {
	struct vbus_kvm   *vkvm;
	struct vbus_shm   *shm;
	struct shm_signal  signal;
	struct _event     *inject;
	int                prio;
	u64                handle;
};

static struct device_signal *to_dsig(struct shm_signal *signal)
{
       return container_of(signal, struct device_signal, signal);
}

static void
_device_signal_inject(struct device_signal *_signal)
{
	struct _eventq *eventq;
	int ret;

	eventq = prio_to_eventq(_signal->vkvm, _signal->prio);

	ret = event_inject(eventq, _signal->inject);
	if (ret < 0)
		_event_put(_signal->inject);
}

static int
device_signal_inject(struct shm_signal *signal)
{
	struct device_signal *_signal = to_dsig(signal);

	_event_get(_signal->inject); /* will be dropped by injection code */
	_device_signal_inject(_signal);

	return 0;
}

static void
device_signal_release(struct shm_signal *signal)
{
	struct device_signal *_signal = to_dsig(signal);
	struct _eventq *eventq;
	unsigned long flags;

	eventq = prio_to_eventq(_signal->vkvm, _signal->prio);

	/*
	 * Change the event-type while holding the lock so we do not race
	 * with any potential threads already processing the queue
	 */
	spin_lock_irqsave(&eventq->lock, flags);
	_signal->inject->data.eventid = VBUS_PCI_EVENT_SHMCLOSE;
	spin_unlock_irqrestore(&eventq->lock, flags);

	/*
	 * do not take a reference to event..last will be dropped once
	 * transmitted.
	 */
	_device_signal_inject(_signal);

	vbus_shm_put(_signal->shm);
	vbus_kvm_put(_signal->vkvm);
	kfree(_signal);
}

static struct shm_signal_ops device_signal_ops = {
	.inject  = device_signal_inject,
	.release = device_signal_release,
};

static struct device_signal *
device_signal_alloc(struct vbus_kvm *vkvm, struct vbus_shm *shm,
		    u32 offset, u32 prio, u64 cookie)
{
	struct device_signal *_signal;
	int ret;

	_signal = kzalloc(sizeof(*_signal), GFP_KERNEL);
	if (!_signal)
		return ERR_PTR(-ENOMEM);

	ret = _signal_init(shm->ptr + offset,
			   &_signal->signal,
			   &device_signal_ops);
	if (ret < 0) {
		kfree(_signal);
		return ERR_PTR(ret);
	}

	_signal->vkvm = vbus_kvm_get(vkvm); /* released with the signal */

	_signal->inject = handle_event_alloc(VBUS_PCI_EVENT_SHMSIGNAL, cookie);
	if (!_signal->inject) {
		shm_signal_put(&_signal->signal);
		return ERR_PTR(-ENOMEM);
	}

	_signal->shm    = shm;
	_signal->prio   = prio;
	vbus_shm_get(shm); /* dropped when the signal is released */

	return _signal;
}

/*
 * ------------------
 * notifiers
 * ------------------
 */

/*
 * This is called whenever our associated vbus emits an event.  We inject
 * these events at the highest logical priority
 */
static int
vbus_notifier(struct notifier_block *nb, unsigned long nr, void *data)
{
	struct vbus_kvm *vkvm = container_of(nb, struct vbus_kvm, vbusnotify);
	struct _eventq *eventq = prio_to_eventq(vkvm, 7);

	switch (nr) {
	case VBUS_EVENT_DEVADD: {
		struct vbus_event_devadd *ev = data;

		devadd_inject(eventq, ev->type, ev->id);
		break;
	}
	case VBUS_EVENT_DEVDROP: {
		unsigned long id = *(unsigned long *)data;

		devdrop_inject(eventq, id);
		break;
	}
	default:
		break;
	}

	return 0;
}

/*
 * ------------------
 * eventq
 * ------------------
 */

static void
_eventq_init(struct _eventq *eventq, int prio)
{
	spin_lock_init(&eventq->lock);
	eventq->prio = prio;
	INIT_WORK(&eventq->wakeup, eventq_reinject);

	eventq->notifier.signal = eventq_notify;

	INIT_LIST_HEAD(&eventq->backlog);
}

static int
_eventq_attach(struct vbus_kvm *vkvm, struct _eventq *eventq, struct file *filp,
	       u32 count, u64 ring, u64 data)
{
	struct kvm_xinterface *kvm = vkvm->kvm;
	struct ioq_ring_head *desc;
	struct ioq *ioq;
	struct _shm *_shm;
	size_t len = IOQ_HEAD_DESC_SIZE(count);
	struct kvm_xvmap *xvmap;
	int ret;

	_shm = _shm_map(vkvm, ring, len);
	if (IS_ERR(_shm))
		return PTR_ERR(_shm);

	desc = _shm->shm.ptr;

	ret = _signal_init(&desc->signal,
			   &eventq->signal,
			   &eventq_signal_ops);
	if (ret < 0) {
		vbus_shm_put(&_shm->shm);
		return ret;
	}

	eventq->shm = &_shm->shm; /* we hold the baseline ref already */
	vbus_kvm_get(vkvm);

	ret = shm_signal_eventfd_bindfile(&eventq->signal, filp);
	if (ret < 0) {
		shm_signal_put(&eventq->signal);
		vbus_shm_put(&_shm->shm);
		return ret;
	}

	shm_signal_get(&eventq->signal); /* take another for eventfd */

	/* FIXME: we should make maxcount configurable */
	ret = vbus_shm_ioq_attach(&_shm->shm, &eventq->signal, 2048, &ioq);
	if (ret < 0) {
		shm_signal_put(&eventq->signal);
		vbus_shm_put(&_shm->shm);
		return ret;
	}

	/*
	 * take refs for the successful ioq allocation, dropped when the
	 * signal releases.
	 */
	vbus_shm_get(&_shm->shm);

	/*
	 * We are going to pre-vmap the eventq data for performance reasons
	 *
	 * This will allow us to skip trying to demand load these particular
	 * pages in the fast-path, and it will also allow us to post writes
	 * from interrupt context (which would not be able to demand-load)
	 */
	len = count * sizeof(struct vbus_pci_event);
	xvmap = kvm->ops->vmap(kvm, data, len);
	if (IS_ERR(xvmap)) {
		ioq_put(ioq);
		return PTR_ERR(xvmap);
	}

	ioq->notifier = &eventq->notifier;

	eventq->ioq            = ioq;
	eventq->ringdata.xvmap = xvmap;
	eventq->ringdata.gpa   = data;

	return 0;
}

static void
_eventq_detach(struct _eventq *eventq)
{
	struct ioq *ioq;
	unsigned long flags;

	spin_lock_irqsave(&eventq->lock, flags);

	ioq = eventq->ioq;
	eventq->ioq = NULL;

	spin_unlock_irqrestore(&eventq->lock, flags);

	if (ioq)
		ioq_put(ioq);
}

/*
 * ------------------
 * hypercall implementation
 * ------------------
 */

static int
hc_deviceopen(struct vbus_kvm *vkvm, void *vargs)
{
	struct vbus_pci_deviceopen *args = vargs;
	struct vbus_client *c = vkvm->client;

	return c->ops->deviceopen(c, vkvm->ctx, args->devid, args->version,
				  &args->handle);
}

static int
hc_deviceclose(struct vbus_kvm *vkvm, void *vargs)
{
	unsigned long *devh = vargs;
	struct vbus_client *c = vkvm->client;

	return c->ops->deviceclose(c, *devh);
}

static int
hc_devicecall(struct vbus_kvm *vkvm, void *vargs)
{
	struct vbus_pci_devicecall *args = vargs;
	struct vbus_client *c = vkvm->client;

	return c->ops->devicecall(c, args->devh, args->func,
				  (void *)args->datap,
				  args->len, args->flags);
}

static int
hc_deviceshm(struct vbus_kvm *vkvm, void *vargs)
{
	struct vbus_pci_deviceshm *args = vargs;
	struct vbus_client    *c = vkvm->client;
	struct shm_signal     *signal = NULL;
	struct _shm           *_shm;
	long                   ret;
	unsigned int           handle;

	_shm = _shm_map(vkvm, args->datap, args->len);
	if (IS_ERR(_shm))
		return PTR_ERR(_shm);

	/*
	 * Establishing a signal is optional
	 */
	if (args->signal.offset != -1) {
		struct device_signal *_signal;

		_signal = device_signal_alloc(vkvm,
					      &_shm->shm,
					      args->signal.offset,
					      args->signal.prio,
					      args->signal.cookie);
		if (IS_ERR(_signal)) {
			ret = PTR_ERR(_signal);
			goto out;
		}

		signal = &_signal->signal;
	}

	ret = c->ops->deviceshm(c, args->devh, args->id,
				&_shm->shm, signal, args->flags, &handle);
	if (ret < 0)
		goto out;

	if (signal)
		ret = handle;

	return ret;

out:
	if (signal)
		shm_signal_put(signal);

	vbus_shm_put(&_shm->shm);
	return ret;
}

struct hc_op {
	int nr;
	int len;
	int dirty;
	int (*func)(struct vbus_kvm *vkvm, void *args);
};

static struct hc_op _hc_devopen = {
	.nr = VBUS_PCI_HC_DEVOPEN,
	.len = sizeof(struct vbus_pci_deviceopen),
	.dirty = 1,
	.func = &hc_deviceopen,
};

static struct hc_op _hc_devclose = {
	.nr = VBUS_PCI_HC_DEVCLOSE,
	.len = sizeof(u64),
	.func = &hc_deviceclose,
};

static struct hc_op _hc_devcall = {
	.nr = VBUS_PCI_HC_DEVCALL,
	.len = sizeof(struct vbus_pci_devicecall),
	.func = &hc_devicecall,
};

static struct hc_op _hc_devshm = {
	.nr = VBUS_PCI_HC_DEVSHM,
	.len = sizeof(struct vbus_pci_deviceshm),
	.dirty = 1,
	.func = &hc_deviceshm,
};

static struct hc_op *hc_ops[] = {
	&_hc_devopen,
	&_hc_devclose,
	&_hc_devcall,
	&_hc_devshm,
};

static int
_hypercall_execute(struct vbus_kvm *vkvm, struct hc_op *op, void *data)
{
	struct vbus_memctx *ctx = vkvm->ctx;
	char                buf[op->len];
	int                 ret;

	ret = ctx->ops->copy_from(ctx, buf, data, op->len);
	if (ret != 0)
		return -EFAULT;

	ret = op->func(vkvm, buf);

	if (ret >= 0 && op->dirty)
		if (ctx->ops->copy_to(ctx, data, buf, op->len))
			return -EFAULT;

	return ret;
}

static int
hypercall_execute(struct vbus_kvm *vkvm, struct vbus_pci_call_desc *args)
{
	struct hc_op *op;

	if (args->vector >= VBUS_PCI_HC_MAX)
		return -EINVAL;

	op = hc_ops[args->vector];

	if (args->len != op->len)
		return -EINVAL;

	return _hypercall_execute(vkvm, op, (void *)args->datap);
}

/*
 * The fastcall-channel-id is passed in by val
 */
static void
fastcall_ioevent(struct kvm_xioevent *ioevent, const void *val)
{
	struct vbus_kvm *vkvm = (struct vbus_kvm *)ioevent->priv;
	unsigned int fccid = *(unsigned int *)val;
	struct _fastcall_channel *fcc;
	int idx;

	idx = srcu_read_lock(&vkvm->srcu);

	fcc = radix_tree_lookup(&vkvm->fastcalls.channels.radix, fccid);
	if (fcc) {
		int ret;

		ret = hypercall_execute(vkvm, &fcc->desc->call);
		fcc->desc->result = ret;
	}

	srcu_read_unlock(&vkvm->srcu, idx);
}

/*
 * The shmsignal-handle is passed in by val
 */
static void
shmsignal_ioevent(struct kvm_xioevent *ioevent, const void *val)
{
	struct vbus_kvm    *vkvm   = (struct vbus_kvm *)ioevent->priv;
	struct vbus_client *c      = vkvm->client;
	unsigned int        handle = *(unsigned int *)val;

	c->ops->shmsignal(c, handle);
}

/*
 * ------------------
 * chardev implementation
 * ------------------
 */

static int
vbus_kvm_chardev_open(struct inode *inode, struct file *filp)
{
	struct vbus *vbus = task_vbus_get(current);
	struct vbus_client *client;
	struct vbus_kvm *vkvm;
	int i;

	if (!vbus)
		return -EPERM;

	client = vbus_client_attach(vbus);
	if (!client) {
		vbus_put(vbus);
		return -ENOMEM;
	}

	vkvm = kzalloc(sizeof(*vkvm), GFP_KERNEL);
	if (!vkvm) {
		vbus_put(vbus);
		vbus_client_put(client);
		return -ENOMEM;
	}

	kref_init(&vkvm->kref);
	mutex_init(&vkvm->lock);
	init_srcu_struct(&vkvm->srcu);
	INIT_RADIX_TREE(&vkvm->fastcalls.channels.radix, GFP_KERNEL);
	INIT_LIST_HEAD(&vkvm->fastcalls.channels.list);
	vkvm->state  = _state_init;
	vkvm->vbus   = vbus;
	vkvm->client = client;
	vkvm->ctx    = _memctx_alloc(vkvm);

	for (i = 0; i < EVENTQ_COUNT; i++)
		_eventq_init(&vkvm->eventq.queues[i], i);

	vkvm->vbusnotify.notifier_call = vbus_notifier;
	vkvm->vbusnotify.priority = 0;

	filp->private_data = vkvm;

	return 0;
}

static int
_negotiate_ioctl(struct vbus_kvm *vkvm, struct vbus_kvm_negotiate *args)
{
	if (vkvm->state != _state_init)
		return -EINVAL;

	if (args->magic != VBUS_KVM_ABI_MAGIC)
		return -EINVAL;

	if (args->version != VBUS_KVM_ABI_VERSION)
		return -EINVAL;

	/*
	 * We have no extended capabilities yet, so we dont care if they set
	 * any option bits.  Just clear them all.
	 */
	args->capabilities = 0;

	vkvm->state = _state_open;

	return 0;
}

#define sigoffset(pos) offsetof(struct vbus_pci_signals, pos)

static int
_open_ioctl(struct vbus_kvm *vkvm, struct vbus_kvm_open *args)
{
	struct kvm_xinterface *kvm;

	if (args->flags != 0)
		return -EINVAL;

	if (vkvm->state != _state_open)
		return -EINVAL;

	kvm = kvm_xinterface_bind(args->vmfd);
	if (IS_ERR(kvm))
		return PTR_ERR(kvm);

	vkvm->kvm = kvm;
	vkvm->state = _state_connect;
	vkvm->mm = get_task_mm(current);

	return VBUS_PCI_HC_VERSION;
}

static int
_sigaddr_assign_ioctl(struct vbus_kvm *vkvm, int addr)
{
	struct kvm_xinterface *kvm = vkvm->kvm;
	struct kvm_xioevent   *ioevent;

	if (vkvm->state != _state_connect)
		return -EINVAL;

	if (vkvm->fastcalls.ioevent || vkvm->shmsignals)
		return -EEXIST;

	ioevent = kvm->ops->ioevent(kvm,
				    addr + sigoffset(fastcall),
				    sizeof(u32),
				    KVM_XIOEVENT_FLAG_PIO);
	if (IS_ERR(ioevent))
		return PTR_ERR(ioevent);

	ioevent->signal = &fastcall_ioevent;
	ioevent->priv   = vkvm;

	vkvm->fastcalls.ioevent = ioevent;

	ioevent = kvm->ops->ioevent(kvm,
				    addr + sigoffset(shmsignal),
				    sizeof(u32),
				    KVM_XIOEVENT_FLAG_PIO);
	if (IS_ERR(ioevent))
		return PTR_ERR(ioevent);

	ioevent->signal = &shmsignal_ioevent;
	ioevent->priv   = vkvm;

	vkvm->shmsignals = ioevent;

	return 0;
}

static int
_eventq_assign_ioctl(struct vbus_kvm *vkvm,
		     struct vbus_kvm_eventq_assign *args)
{
	struct file *input = NULL;
	struct eventfd_ctx *output = NULL;
	struct _eventq *eventq;
	int fd = 0;
	int ret = 0;

	if (args->flags != 0)
		return -EINVAL;

	if (vkvm->state != _state_connect)
		return -EINVAL;

	mutex_lock(&vkvm->lock);

	if (args->queue != vkvm->eventq.count
	    || args->queue >= ARRAY_SIZE(vkvm->eventq.queues)) {
		ret = -EINVAL;
		goto fail;
	}

	eventq = &vkvm->eventq.queues[args->queue];

	output = eventfd_ctx_fdget(args->fd);
	if (IS_ERR(output)) {
		ret = PTR_ERR(output);
		goto fail;
	}

	fd = get_unused_fd();
	if (fd < 0) {
		ret = fd;
		goto fail;
	}

	input = eventfd_file_create(0, 0);
	if (IS_ERR(input)) {
		ret = PTR_ERR(input);
		goto fail;
	}

	ret = _eventq_attach(vkvm, eventq, input,
			     args->count, args->ring, args->data);
	if (ret < 0)
		goto fail;

	fd_install(fd, input); /* cannot fail after installing the fd */

	eventq->eventfd = output;
	vkvm->eventq.count++;

	mutex_unlock(&vkvm->lock);

	return fd;

fail:
	if (fd > 0)
		put_unused_fd(fd);

	if (input)
		fput(input);

	if (output)
		eventfd_ctx_put(output);

	mutex_unlock(&vkvm->lock);

	return ret;
}

static int
_ready_ioctl(struct vbus_kvm *vkvm)
{
	int ret;

	if (vkvm->state != _state_connect)
		return -EINVAL;

	ret = vbus_notifier_register(vkvm->vbus, &vkvm->vbusnotify);
	if (ret < 0)
		return ret;

	vkvm->state = _state_ready;

	return 0;
}

static int
_fcc_assign_ioctl(struct vbus_kvm *vkvm,
		  struct vbus_pci_call_desc *args)
{
	struct _fastcall_channel *_fcc;
	struct _shm *_shm;
	int ret;

	_fcc = kzalloc(sizeof(*_fcc), GFP_KERNEL);
	if (!_fcc)
		return -ENOMEM;

	if (args->len != sizeof(struct vbus_pci_fastcall_desc))
		return -EINVAL;

	_shm = _shm_map(vkvm, args->datap, args->len);
	if (IS_ERR(_shm)) {
		kfree(_fcc);
		return PTR_ERR(_shm);
	}

	_fcc->id   = args->vector;
	_fcc->shm  = &_shm->shm;
	_fcc->desc = (struct vbus_pci_fastcall_desc *)_fcc->shm->ptr;

	mutex_lock(&vkvm->lock);

	ret = radix_tree_insert(&vkvm->fastcalls.channels.radix,
				_fcc->id, _fcc);
	if (ret < 0) {
		vbus_shm_put(_fcc->shm);
		kfree(_fcc);
	} else
		list_add_tail(&_fcc->list, &vkvm->fastcalls.channels.list);

	mutex_unlock(&vkvm->lock);

	return ret;
}

static int
_fcc_deassign(struct vbus_kvm *vkvm, int id)
{
	struct _fastcall_channel *_fcc;

	mutex_lock(&vkvm->lock);
	_fcc = radix_tree_delete(&vkvm->fastcalls.channels.radix, id);
	if (_fcc)
		list_del(&_fcc->list);
	mutex_unlock(&vkvm->lock);

	if (!_fcc)
		return -ENOENT;

	synchronize_srcu(&vkvm->srcu);

	vbus_shm_put(_fcc->shm);
	kfree(_fcc);

	return 0;
}

static ssize_t
vbus_kvm_chardev_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	struct vbus_kvm *vkvm = filp->private_data;

	switch (ioctl) {
	case VBUS_KVM_NEGOTIATE:
		return _negotiate_ioctl(vkvm,
					(struct vbus_kvm_negotiate *)arg);
	case VBUS_KVM_OPEN:
		return _open_ioctl(vkvm, (struct vbus_kvm_open *)arg);
	case VBUS_KVM_SIGADDR_ASSIGN:
		return _sigaddr_assign_ioctl(vkvm, *(__u32 *)arg);
	case VBUS_KVM_EVENTQ_ASSIGN:
		return _eventq_assign_ioctl(vkvm,
					    (struct vbus_kvm_eventq_assign *)arg);
	case VBUS_KVM_READY:
		return _ready_ioctl(vkvm);
	case VBUS_KVM_SLOWCALL:
		return hypercall_execute(vkvm,
					 (struct vbus_pci_call_desc *)arg);
	case VBUS_KVM_FCC_ASSIGN:
		return _fcc_assign_ioctl(vkvm,
					 (struct vbus_pci_call_desc *)arg);
	case VBUS_KVM_FCC_DEASSIGN:
		return _fcc_deassign(vkvm, *(__u32 *)arg);
	default:
		return -EINVAL;
	}
}

static void
_fastcall_channels_release(struct vbus_kvm *vkvm)
{
	struct _fastcall_channel *_fcc, *tmp;
	struct list_head *head = &vkvm->fastcalls.channels.list;

	list_for_each_entry_safe(_fcc, tmp, head, list)
		_fcc_deassign(vkvm, _fcc->id);
}

static int
vbus_kvm_chardev_release(struct inode *inode, struct file *filp)
{
	struct vbus_kvm *vkvm = filp->private_data;
	int i;

	for (i = 0; i < vkvm->eventq.count; i++)
		_eventq_detach(&vkvm->eventq.queues[i]);

	_fastcall_channels_release(vkvm);
	if (vkvm->fastcalls.ioevent)
		kvm_xioevent_deassign(vkvm->fastcalls.ioevent);
	if (vkvm->shmsignals)
		kvm_xioevent_deassign(vkvm->shmsignals);

	if (vkvm->state == _state_ready)
		vbus_notifier_unregister(vkvm->vbus, &vkvm->vbusnotify);

	if (vkvm->mm)
		mmput(vkvm->mm);

	vbus_memctx_put(vkvm->ctx);
	vbus_client_put(vkvm->client);

	vbus_put(vkvm->vbus);

	vbus_kvm_put(vkvm);

	return 0;
}

static const struct file_operations vbus_kvm_chardev_ops = {
	.open           = vbus_kvm_chardev_open,
	.unlocked_ioctl = vbus_kvm_chardev_ioctl,
	.compat_ioctl   = vbus_kvm_chardev_ioctl,
	.release        = vbus_kvm_chardev_release,
};

static struct miscdevice vbus_kvm_chardev = {
	MISC_DYNAMIC_MINOR,
	"vbus-kvm",
	&vbus_kvm_chardev_ops,
};

static int __init
vbus_kvm_init(void)
{
	int i;

	/* sanity check the hc_ops structure */
	for (i = 0; i < ARRAY_SIZE(hc_ops); i++) {
		struct hc_op *op = hc_ops[i];

		BUG_ON(op->nr != i);
	}

	return misc_register(&vbus_kvm_chardev);
}

static void __exit
vbus_kvm_cleanup(void)
{
	misc_deregister(&vbus_kvm_chardev);
}

module_init(vbus_kvm_init);
module_exit(vbus_kvm_cleanup);
