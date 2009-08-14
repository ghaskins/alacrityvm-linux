#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>
#include <linux/vbus.h>
#include <linux/vbus_client.h>
#include "vbus.h"

static int
nodeptr_item_compare(struct rb_node *lhs, struct rb_node *rhs)
{
	unsigned long l = (unsigned long)lhs;
	unsigned long r = (unsigned long)rhs;

	return l - r;
}

static int
nodeptr_key_compare(const void *key, struct rb_node *node)
{
	unsigned long item = (unsigned long)node;
	unsigned long _key = *(unsigned long *)key;

	return _key - item;
}

static struct map_ops nodeptr_map_ops = {
	.key_compare = &nodeptr_key_compare,
	.item_compare = &nodeptr_item_compare,
};

struct _signal {
	struct kref kref;
	struct rb_node node;
	struct list_head list;
	struct shm_signal *signal;
};

struct _connection {
	struct kref kref;
	struct rb_node node;
	struct list_head signals;
	struct vbus_connection *conn;
	int closed:1;
};

static inline void _signal_get(struct _signal *_signal)
{
	kref_get(&_signal->kref);
}

static inline void _signal_release(struct kref *kref)
{
	struct _signal *_signal = container_of(kref, struct _signal, kref);

	shm_signal_put(_signal->signal);
	kfree(_signal);
}

static inline void _signal_put(struct _signal *_signal)
{
	kref_put(&_signal->kref, _signal_release);
}

static inline void conn_get(struct _connection *_conn)
{
	kref_get(&_conn->kref);
}

static inline void conn_close(struct _connection *_conn)
{
	struct vbus_connection *conn = _conn->conn;

	if (conn->ops->close)
		conn->ops->close(conn);

	_conn->closed = true;
}

static inline void _conn_release(struct kref *kref)
{
	struct _connection *_conn;
	struct _signal *_signal, *tmp;

	_conn = container_of(kref, struct _connection, kref);

	if (!_conn->closed)
		conn_close(_conn);

	list_for_each_entry_safe(_signal, tmp, &_conn->signals, list) {
		list_del(&_signal->list);
		_signal_put(_signal);
	}

	vbus_connection_put(_conn->conn);
	kfree(_conn);

}

static inline void conn_put(struct _connection *_conn)
{
	kref_put(&_conn->kref, _conn_release);
}

struct _client {
	struct mutex lock;
	struct map conn_map;
	struct map signal_map;
	struct vbus *vbus;
	struct vbus_client client;
};

struct _connection *to_conn(struct rb_node *node)
{
	return node ? container_of(node, struct _connection, node) : NULL;
}

static struct _signal *to_signal(struct rb_node *node)
{
	return node ? container_of(node, struct _signal, node) : NULL;
}

static struct _client *to_client(struct vbus_client *client)
{
	return container_of(client, struct _client, client);
}

static struct _connection *
connection_find(struct _client *c, unsigned long devid)
{
	struct _connection *_conn;

	/*
	 * We could, in theory, cast devid to _conn->node, but this would
	 * be pretty stupid to trust.  Therefore, we must validate that
	 * the pointer is legit by seeing if it exists in our conn_map
	 */

	mutex_lock(&c->lock);

	_conn = to_conn(map_find(&c->conn_map, &devid));
	if (likely(_conn))
		conn_get(_conn);

	mutex_unlock(&c->lock);

	return _conn;
}

static int
_deviceopen(struct vbus_client *client, struct vbus_memctx *ctx,
	    __u32 devid, __u32 version, __u64 *devh)
{
	struct _client *c = to_client(client);
	struct vbus_connection *conn;
	struct _connection *_conn;
	struct vbus_device_interface *intf = NULL;
	int ret;

	/*
	 * We only get here if the device has never been opened before,
	 * so we need to create a new connection
	 */
	ret = vbus_interface_find(c->vbus, devid, &intf);
	if (ret < 0)
		return ret;

	ret = intf->ops->connect(intf, ctx, version, &conn);
	kobject_put(&intf->kobj);
	if (ret < 0)
		return ret;

	_conn = kzalloc(sizeof(*_conn), GFP_KERNEL);
	if (!_conn) {
		vbus_connection_put(conn);
		return -ENOMEM;
	}

	kref_init(&_conn->kref);
	_conn->conn = conn;

	INIT_LIST_HEAD(&_conn->signals);

	mutex_lock(&c->lock);
	ret = map_add(&c->conn_map, &_conn->node);
	mutex_unlock(&c->lock);

	if (ret < 0) {
		conn_put(_conn);
		return ret;
	}

	/* in theory, &_conn->node should be unique */
	*devh = (__u64)&_conn->node;

	return 0;

}

/*
 * Assumes client->lock is held (or we are releasing and dont need to lock)
 */
static void
conn_del(struct _client *c, struct _connection *_conn)
{
	struct _signal *_signal, *tmp;

	/* Delete and release each opened queue */
	list_for_each_entry_safe(_signal, tmp, &_conn->signals, list) {
		map_del(&c->signal_map, &_signal->node);
		_signal_put(_signal);
	}

	map_del(&c->conn_map, &_conn->node);
}

static int
_deviceclose(struct vbus_client *client, __u64 devh)
{
	struct _client *c = to_client(client);
	struct _connection *_conn;

	mutex_lock(&c->lock);

	_conn = to_conn(map_find(&c->conn_map, &devh));
	if (likely(_conn))
		conn_del(c, _conn);

	mutex_unlock(&c->lock);

	if (unlikely(!_conn))
		return -ENOENT;

	conn_close(_conn);

	/* this _put is the compliment to the _get performed at _deviceopen */
	conn_put(_conn);

	return 0;
}

static int
_devicecall(struct vbus_client *client,
	    __u64 devh, __u32 func, void *data, __u32 len, __u32 flags)
{
	struct _client *c = to_client(client);
	struct _connection *_conn;
	struct vbus_connection *conn;
	int ret;

	_conn = connection_find(c, devh);
	if (!_conn)
		return -ENOENT;

	conn = _conn->conn;

	ret = conn->ops->call(conn, func, data, len, flags);

	conn_put(_conn);

	return ret;
}

static int
_deviceshm(struct vbus_client *client,
	   __u64 devh,
	   __u32 id,
	   struct vbus_shm *shm,
	   struct shm_signal *signal,
	   __u32 flags,
	   __u64 *handle)
{
	struct _client *c = to_client(client);
	struct _signal *_signal = NULL;
	struct _connection *_conn;
	struct vbus_connection *conn;
	int ret;

	if (handle)
		*handle = 0;

	_conn = connection_find(c, devh);
	if (!_conn)
		return -ENOENT;

	conn = _conn->conn;

	ret = conn->ops->shm(conn, id, shm, signal, flags);
	if (ret < 0) {
		conn_put(_conn);
		return ret;
	}

	if (handle && signal) {
		_signal = kzalloc(sizeof(*_signal), GFP_KERNEL);
		if (!_signal) {
			conn_put(_conn);
			return -ENOMEM;
		}

		 /* one for map-ref, one for list-ref */
		kref_set(&_signal->kref, 2);
		_signal->signal = signal;
		shm_signal_get(signal);

		mutex_lock(&c->lock);
		ret = map_add(&c->signal_map, &_signal->node);
		list_add_tail(&_signal->list, &_conn->signals);
		mutex_unlock(&c->lock);

		if (!ret)
			*handle = (__u64)&_signal->node;
	}

	conn_put(_conn);

	return 0;
}

static int
_shmsignal(struct vbus_client *client, __u64 handle)
{
	struct _client *c = to_client(client);
	struct _signal *_signal;

	mutex_lock(&c->lock);

	_signal = to_signal(map_find(&c->signal_map, &handle));
	if (likely(_signal))
		_signal_get(_signal);

	mutex_unlock(&c->lock);

	if (!_signal)
		return -ENOENT;

	_shm_signal_wakeup(_signal->signal);

	_signal_put(_signal);

	return 0;
}

static void
_release(struct vbus_client *client)
{
	struct _client *c = to_client(client);
	struct rb_node *node;

	/* Drop all of our open connections */
	while ((node = rb_first(&c->conn_map.root))) {
		struct _connection *_conn = to_conn(node);

		conn_del(c, _conn);
		conn_put(_conn);
	}

	vbus_put(c->vbus);
	kfree(c);
}

struct vbus_client_ops _client_ops = {
	.deviceopen  = _deviceopen,
	.deviceclose = _deviceclose,
	.devicecall  = _devicecall,
	.deviceshm   = _deviceshm,
	.shmsignal   = _shmsignal,
	.release     = _release,
};

struct vbus_client *vbus_client_attach(struct vbus *vbus)
{
	struct _client *c;

	BUG_ON(!vbus);

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return NULL;

	kref_init(&c->client.kref);
	c->client.ops = &_client_ops;

	mutex_init(&c->lock);
	map_init(&c->conn_map, &nodeptr_map_ops);
	map_init(&c->signal_map, &nodeptr_map_ops);
	c->vbus = vbus_get(vbus);

	return &c->client;
}
EXPORT_SYMBOL_GPL(vbus_client_attach);

/*
 * memory context helpers
 */

static unsigned long
current_memctx_copy_to(struct vbus_memctx *ctx, void *dst, const void *src,
		       unsigned long len)
{
	return copy_to_user(dst, src, len);
}

static unsigned long
current_memctx_copy_from(struct vbus_memctx *ctx, void *dst, const void *src,
			 unsigned long len)
{
	return copy_from_user(dst, src, len);
}

static void
current_memctx_release(struct vbus_memctx *ctx)
{
	panic("dropped last reference to current_memctx");
}

static struct vbus_memctx_ops current_memctx_ops = {
	.copy_to   = &current_memctx_copy_to,
	.copy_from = &current_memctx_copy_from,
	.release   = &current_memctx_release,
};

static struct vbus_memctx _current_memctx =
	VBUS_MEMCTX_INIT((&current_memctx_ops));

struct vbus_memctx *current_memctx = &_current_memctx;

/*
 * task_mem allows you to have a copy_from_user/copy_to_user like
 * environment, except that it supports copying to tasks other
 * than "current" as ctu/cfu() do
 */
struct task_memctx {
	struct task_struct *task;
	struct vbus_memctx ctx;
};

static struct task_memctx *to_task_memctx(struct vbus_memctx *ctx)
{
	return container_of(ctx, struct task_memctx, ctx);
}

static unsigned long
task_memctx_copy_to(struct vbus_memctx *ctx, void *dst, const void *src,
		    unsigned long n)
{
	struct task_memctx *tm = to_task_memctx(ctx);
	struct task_struct *p = tm->task;

	while (n) {
		unsigned long offset = ((unsigned long)dst)%PAGE_SIZE;
		unsigned long len = PAGE_SIZE - offset;
		int ret;
		struct page *pg;
		void *maddr;

		if (len > n)
			len = n;

		down_read(&p->mm->mmap_sem);
		ret = get_user_pages(p, p->mm,
				     (unsigned long)dst, 1, 1, 0, &pg, NULL);

		if (ret != 1) {
			up_read(&p->mm->mmap_sem);
			break;
		}

		maddr = kmap_atomic(pg, KM_USER0);
		memcpy(maddr + offset, src, len);
		kunmap_atomic(maddr, KM_USER0);
		set_page_dirty_lock(pg);
		put_page(pg);
		up_read(&p->mm->mmap_sem);

		src += len;
		dst += len;
		n -= len;
	}

	return n;
}

static unsigned long
task_memctx_copy_from(struct vbus_memctx *ctx, void *dst, const void *src,
		      unsigned long n)
{
	struct task_memctx *tm = to_task_memctx(ctx);
	struct task_struct *p = tm->task;

	while (n) {
		unsigned long offset = ((unsigned long)src)%PAGE_SIZE;
		unsigned long len = PAGE_SIZE - offset;
		int ret;
		struct page *pg;
		void *maddr;

		if (len > n)
			len = n;

		down_read(&p->mm->mmap_sem);
		ret = get_user_pages(p, p->mm,
				     (unsigned long)src, 1, 1, 0, &pg, NULL);

		if (ret != 1) {
			up_read(&p->mm->mmap_sem);
			break;
		}

		maddr = kmap_atomic(pg, KM_USER0);
		memcpy(dst, maddr + offset, len);
		kunmap_atomic(maddr, KM_USER0);
		put_page(pg);
		up_read(&p->mm->mmap_sem);

		src += len;
		dst += len;
		n -= len;
	}

	return n;
}

static void
task_memctx_release(struct vbus_memctx *ctx)
{
	struct task_memctx *tm = to_task_memctx(ctx);

	put_task_struct(tm->task);
	kfree(tm);
}

static struct vbus_memctx_ops task_memctx_ops = {
	.copy_to   = &task_memctx_copy_to,
	.copy_from = &task_memctx_copy_from,
	.release   = &task_memctx_release,
};

struct vbus_memctx *task_memctx_alloc(struct task_struct *task)
{
	struct task_memctx *tm;

	tm = kzalloc(sizeof(*tm), GFP_KERNEL);
	if (!tm)
		return NULL;

	get_task_struct(task);

	tm->task = task;
	vbus_memctx_init(&tm->ctx, &task_memctx_ops);

	return &tm->ctx;
}
EXPORT_SYMBOL_GPL(task_memctx_alloc);
