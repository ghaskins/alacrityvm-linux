/*
 * Implements a "localhost connector" for vbus as an example of what needs to
 * be implemented for a basic connector
 */

#include <linux/vbus.h>
#include <linux/vbus_client.h>
#include <linux/vbus_driver.h>
#include <linux/radix-tree.h>
#include <linux/slab.h>
#include <linux/list.h>

MODULE_AUTHOR("Gregory Haskins");
MODULE_LICENSE("GPL");
MODULE_VERSION("1");

#define VBUS_MAX_DEVTYPE_LEN 128

static int downcall_devopen(unsigned int id, unsigned int version, u64 *handle);
static int downcall_devclose(u64 handle);
static int downcall_devshm(u64 devh, unsigned int id, void *ptr, size_t len,
			   size_t offset, unsigned long cookie);
static int downcall_devcall(u64 handle, u32 func, void *data, size_t len,
			    int flags);
static int downcall_shmsignal(unsigned int handle);

/*
 *==================================================================
 * "guest"-side code
 *------------------------------------------------------------------
 */

struct vbus_localhost_guest {
	struct mutex           lock;
	struct radix_tree_root devices;
};

static struct vbus_localhost_guest _localhost_guest;

/*
 * ---------------
 *  guest-side signal - signaling from the guest-side results in a downcall
 * ---------------
 */

struct guest_signal {
	struct shm_signal  signal;
	unsigned int       handle;
	struct list_head   list;
};

static struct guest_signal *
to_gsignal(struct shm_signal *signal)
{
       return container_of(signal, struct guest_signal, signal);
}

static int
guest_signal_inject(struct shm_signal *signal)
{
	struct guest_signal *_signal = to_gsignal(signal);

	downcall_shmsignal(_signal->handle);

	return 0;
}

static void
guest_signal_release(struct shm_signal *signal)
{
	struct guest_signal *_signal = to_gsignal(signal);
	kfree(_signal);
}

static struct shm_signal_ops guest_signal_ops = {
	.inject  = guest_signal_inject,
	.release = guest_signal_release,
};


/*
 * ---------------
 * proxy device
 * ---------------
 */

struct guest_device {
	char                     type[VBUS_MAX_DEVTYPE_LEN];
	u64                      handle;
	struct list_head         shms;
	struct vbus_device_proxy dev;
};

static struct guest_device *
to_dev(struct vbus_device_proxy *dev)
{
	return container_of(dev, struct guest_device, dev);
}

static int
guest_device_open(struct vbus_device_proxy *dev, int version, int flags)
{
	struct guest_device *_dev = to_dev(dev);
	return downcall_devopen(_dev->dev.id, version, &_dev->handle);
}

static int
guest_device_close(struct vbus_device_proxy *dev, int flags)
{
	struct guest_device *_dev = to_dev(dev);

	while (!list_empty(&_dev->shms)) {
		struct guest_signal *_signal;

		_signal = list_first_entry(&_dev->shms, struct guest_signal,
					   list);

		list_del(&_signal->list);
		shm_signal_put(&_signal->signal);
	}

	return downcall_devclose(_dev->handle);
}

static int
guest_device_shm(struct vbus_device_proxy *dev, const char *name, int id,
		 int prio, void *ptr, size_t len,
		 struct shm_signal_desc *sdesc, struct shm_signal **signal,
		 int flags)
{
	struct guest_device *_dev = to_dev(dev);
	struct guest_signal *_signal = NULL;
	long offset = -1;
	int ret;

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

		sdesc->magic = SHM_SIGNAL_MAGIC;
		sdesc->ver   = SHM_SIGNAL_VER;

		shm_signal_init(&_signal->signal, shm_locality_north,
				&guest_signal_ops, sdesc);

		/*
		 * take another reference for the host.  This is dropped
		 * by a SHMCLOSE event
		 */
		shm_signal_get(&_signal->signal);

		offset = (long)sdesc - (long)ptr;
	}

	ret = downcall_devshm(_dev->handle, id, ptr, len, offset,
			      (unsigned long)_signal);
	if (ret < 0) {
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

	if (signal) {
		BUG_ON(ret < 0);

		_signal->handle = ret;

		mutex_lock(&_localhost_guest.lock);
		list_add_tail(&_signal->list, &_dev->shms);
		mutex_unlock(&_localhost_guest.lock);

		shm_signal_get(&_signal->signal);
		*signal = &_signal->signal;
	}

	return 0;
}

static int
guest_device_call(struct vbus_device_proxy *dev, u32 func,
		void *data, size_t len, int flags)
{
	struct guest_device *_dev = to_dev(dev);
	return downcall_devcall(_dev->handle, func, __pa(data), len, flags);
}

static void
guest_device_release(struct vbus_device_proxy *dev)
{
	struct guest_device *_dev = to_dev(dev);
	kfree(_dev);
}

static struct vbus_device_proxy_ops guest_device_ops = {
	.open    = guest_device_open,
	.close   = guest_device_close,
	.shm     = guest_device_shm,
	.call    = guest_device_call,
	.release = guest_device_release,
};

/*
 * ---------------
 * upcalls
 * ---------------
 */

static void
upcall_devadd(const char *type, unsigned long id)
{
	struct guest_device *_dev;
	int ret;

	_dev = kzalloc(sizeof(*_dev), GFP_KERNEL);
	BUG_ON(!_dev);

	INIT_LIST_HEAD(&_dev->shms);

	strncpy(_dev->type, type, VBUS_MAX_DEVTYPE_LEN);
	_dev->dev.type = _dev->type;
	_dev->dev.id   = id;
	_dev->dev.ops  = &guest_device_ops;

	dev_set_name(&_dev->dev.dev, "%lld", id);

	mutex_lock(&_localhost_guest.lock);
	ret = radix_tree_insert(&_localhost_guest.devices, id, _dev);
	BUG_ON(ret < 0);
	mutex_unlock(&_localhost_guest.lock);

	ret = vbus_device_proxy_register(&_dev->dev);
	BUG_ON(ret < 0);
}

static void
upcall_devdrop(unsigned long id)
{
	struct guest_device *_dev;

	mutex_lock(&_localhost_guest.lock);
	_dev = radix_tree_delete(&_localhost_guest.devices, id);
	mutex_unlock(&_localhost_guest.lock);

	BUG_ON(!_dev);

	vbus_device_proxy_unregister(&_dev->dev);
}

static void
upcall_shmsignal(unsigned long cookie)
{
	struct guest_signal *_signal = (struct guest_signal *)cookie;
	_shm_signal_wakeup(&_signal->signal);
}

/* Drop the reference taken during the DEVICESHM call */
static void
upcall_shmclose(unsigned long cookie)
{
	struct guest_signal *_signal = (struct guest_signal *)cookie;
	shm_signal_put(&_signal->signal);
}

/*
 *==================================================================
 * "host"-side code
 *------------------------------------------------------------------
 */

struct vbus_localhost_host {
	struct vbus           *vbus;
	struct vbus_client    *client;
	struct vbus_memctx     ctx;
	struct notifier_block  notify;
};

static struct vbus_localhost_host _localhost_host;

/*
 * ---------------
 *  host-side signal - signaling from the host-side results in an upcall
 * ---------------
 */

struct host_signal {
	struct shm_signal signal;
	unsigned long cookie;
};

static struct host_signal *
to_hsignal(struct shm_signal *signal)
{
       return container_of(signal, struct host_signal, signal);
}

static int
host_signal_inject(struct shm_signal *signal)
{
	struct host_signal *_signal = to_hsignal(signal);

	upcall_shmsignal(_signal->cookie);

	return 0;
}

static void
host_signal_release(struct shm_signal *signal)
{
	struct host_signal *_signal = to_hsignal(signal);

	upcall_shmclose(_signal->cookie);
	kfree(_signal);
}

static struct shm_signal_ops host_signal_ops = {
	.inject  = host_signal_inject,
	.release = host_signal_release,
};

/*
 * ---------------
 * shared-memory
 * ---------------
 */

static void
_shm_release(struct vbus_shm *shm)
{
	kfree(shm);
}

static struct vbus_shm_ops _shm_ops = {
	.release = _shm_release,
};


/*
 * We would normally want to take the ptr/len and translate the
 * gpa and vmap it into our address space.  Since this is a trivial
 * LOCALHOST example that lives in the same kernel address space, we simply
 * just set the pointer directly.
 */
static struct vbus_shm *
_shmap(void *ptr, size_t len)
{
	struct vbus_shm *shm;

	shm = kzalloc(sizeof(*shm), GFP_KERNEL);
	if (!shm)
		return ERR_PTR(-ENOMEM);

	vbus_shm_init(shm, &_shm_ops, ptr, len);

	return shm;
}

/*
 * ---------------
 * downcalls
 * ---------------
 */

static int
downcall_devopen(unsigned int id, unsigned int version, u64 *handle)
{
	struct vbus_client *c = _localhost_host.client;
	return c->ops->deviceopen(c, &_localhost_host.ctx, id, version, handle);
}

static int
downcall_devclose(u64 handle)
{
	struct vbus_client *c = _localhost_host.client;
	return c->ops->deviceclose(c, handle);
}

static int
downcall_devshm(u64 devh, unsigned int id, void *ptr, size_t len,
		size_t offset, unsigned long cookie)
{
	struct vbus_client    *c = _localhost_host.client;
	struct shm_signal     *signal = NULL;
	struct vbus_shm       *shm;
	unsigned int           handle;
	int ret;

	shm = _shmap(ptr, len);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	/*
	 * Establishing a signal is optional
	 */
	if (offset != -1) {
		struct host_signal *_signal;
		struct shm_signal_desc *desc = ptr + offset;

		if (desc->magic != SHM_SIGNAL_MAGIC)
			return -EINVAL;

		if (desc->ver != SHM_SIGNAL_VER)
			return -EINVAL;

		_signal = kzalloc(sizeof(*_signal), GFP_KERNEL);
		if (!_signal)
			return -ENOMEM;

		shm_signal_init(&_signal->signal, shm_locality_south,
				&host_signal_ops, desc);

		_signal->cookie = cookie;
		signal = &_signal->signal;
	}

	ret = c->ops->deviceshm(c, devh, id, shm, signal, 0, &handle);
	if (ret < 0)
		goto out;

	if (signal)
		ret = handle;

	return ret;

out:
	if (signal)
		shm_signal_put(signal);

	vbus_shm_put(shm);
	return ret;

}

static int
downcall_devcall(u64 handle, u32 func, void *data, size_t len, int flags)
{
	struct vbus_client *c = _localhost_host.client;
	return c->ops->devicecall(c, handle, func, data, len, flags);
}

static int
downcall_shmsignal(unsigned int handle)
{
	struct vbus_client *c = _localhost_host.client;
	return c->ops->shmsignal(c, handle);
}

/* called whenever our associated vbus emits an event */
static int
hotswap_notifier(struct notifier_block *nb, unsigned long nr, void *data)
{
	switch (nr) {
	case VBUS_EVENT_DEVADD: {
		struct vbus_event_devadd *ev = data;
		upcall_devadd(ev->type, ev->id);
		break;
	}
	case VBUS_EVENT_DEVDROP: {
		unsigned long id = *(unsigned long *)data;
		upcall_devdrop(id);
		break;
	}
	default:
		break;
	}

	return 0;
}

/*
 * -----------------
 * memory-context routines
 *
 * Since we have both sides on the same kernel, we do not need to do
 * anything fancy other than reverse the __pa() translation of the
 * "foreign" pointer with __va()
 * -----------------
 */

static unsigned long
_memctx_copy_to(struct vbus_memctx *ctx, void *dst, const void *src,
	       unsigned long n)
{
	void *_dst = __va(dst);

	memcpy(_dst, src, n);

	return 0;
}

static unsigned long
_memctx_copy_from(struct vbus_memctx *ctx, void *dst, const void *src,
		  unsigned long n)
{
	void *_src = __va(src);

	memcpy(dst, _src, n);

	return 0;
}

static struct vbus_memctx_ops _memctx_ops = {
	.copy_to   = &_memctx_copy_to,
	.copy_from = &_memctx_copy_from,
};

static int __init
vbus_localhost_init(void)
{
	struct vbus *vbus;
	struct vbus_client *client;
	int ret;

	mutex_init(&_localhost_guest.lock);
	INIT_RADIX_TREE(&_localhost_guest.devices, GFP_KERNEL);

	/*
	 * Attach to a pre-named bus ("localhost-bus").  Normally, you may
	 * want use task_vbus_get(current) to associate with whatever
	 * container is assigned to the current process.  Since this
	 * is an example, we will keep things simple
	 */
	vbus = vbus_find("localhost-bus");
	if (!vbus) {
		printk(KERN_ERR "could not attach to \"localhost-bus\"\n");
		return -EINVAL;
	}

	_localhost_host.vbus = vbus;

	/*
	 * A client interface makes certain connector tasks easier.  It
	 * is purely optional at the discretion of the connector designer
	 */
	client = vbus_client_attach(vbus);
	if (!client) {
		vbus_put(vbus);
		return -ENOMEM;
	}

	_localhost_host.client = client;

	vbus_memctx_init(&_localhost_host.ctx, &_memctx_ops);

	/*
	 * Register to be notified when the container is modified
	 */
	_localhost_host.notify.notifier_call = hotswap_notifier;
	_localhost_host.notify.priority = 0;
	ret = vbus_notifier_register(vbus, &_localhost_host.notify);
	if (ret < 0) {
		vbus_client_put(client);
		vbus_put(vbus);
		return ret;
	}

	return 0;
}

static void __exit
vbus_localhost_cleanup(void)
{
	if (_localhost_host.client)
		vbus_client_put(_localhost_host.client);

	if (_localhost_host.vbus)
		vbus_put(_localhost_host.vbus);
}

module_init(vbus_localhost_init);
module_exit(vbus_localhost_cleanup);
