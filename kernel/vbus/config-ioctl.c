#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/random.h>
#include <linux/vbus.h>
#include <linux/vbus_admin.h>
#include <linux/slab.h>

#include "vbus.h"

#define MAX_BUS_NAME 256
#define MAX_DEV_NAME (MAX_BUS_NAME + 256)

struct vbus_admin {
	struct mutex lock;
	struct vbus *bus;
	unsigned char name[MAX_BUS_NAME];
	struct list_head devs;
	unsigned long devindex;
};

struct _device {
	unsigned char         name[MAX_DEV_NAME];
	struct vbus_devshell *ds;
	struct list_head      list;
};

#define remain(buf, pos) (sizeof(buf) - (pos - buf))

static int
vbus_admin_chardev_open(struct inode *inode, struct file *filp)
{
	struct vbus *vbus = task_vbus_get(current);
	struct vbus_admin *vadmin;
	unsigned char uuid[16];
	unsigned char *buf;
	int i;
	int ret;

	if (vbus) {
		vbus_put(vbus);
		return -EEXIST;
	}

	vadmin = kzalloc(sizeof(*vadmin), GFP_KERNEL);
	if (!vadmin)
		return -ENOMEM;

	mutex_init(&vadmin->lock);
	INIT_LIST_HEAD(&vadmin->devs);

	buf = vadmin->name;

	generate_random_uuid(uuid);

	buf += scnprintf(buf, remain(vadmin->name, buf),
			 "%s-%d-", current->comm, current->pid);

	for (i = 0; i < 16; i++) {
		buf += scnprintf(buf, remain(vadmin->name, buf),
				"%02x", uuid[i]);
		if (i == 3 || i == 5 || i == 7 || i == 9)
			buf += strlcpy(buf, "-", remain(vadmin->name, buf));
	}

	ret = vbus_create(vadmin->name, &vbus);
	if (ret < 0)
		goto fail;

	ret = vbus_associate(vbus, current);
	if (ret < 0)
		goto fail;

	rcu_assign_pointer(current->vbus, vbus);

	vadmin->bus = vbus;
	filp->private_data = vadmin;

	return 0;

fail:
	if (vbus)
		vbus_put(vbus);

	kfree(vadmin);

	return ret;
}

static int
_negotiate_ioctl(struct vbus_admin *vadmin, struct vbus_admin_negotiate *args)
{
	if (args->magic != VBUS_ADMIN_MAGIC)
		return -EINVAL;

	if (args->version != VBUS_ADMIN_VERSION)
		return -EINVAL;

	/*
	 * We have no extended capabilities yet, so we dont care if they set
	 * any option bits.  Just clear them all.
	 */
	args->capabilities = 0;

	return 0;
}

static int
_dev_create_ioctl(struct vbus_admin *vadmin,
		  struct vbus_admin_dev_create *args)
{
	struct vbus_devclass *dc;
	struct vbus_devshell *ds = NULL;
	struct vbus_device *dev = NULL;
	struct _device *_dev = NULL;
	char type[128];
	int ret;
	size_t namelen;

	if (strnlen_user((void *)args->type, sizeof(type)) > sizeof(type))
		return -EINVAL;

	ret = strncpy_from_user(type, (void *)args->type, sizeof(type));
	if (ret < 0)
		return ret;

	dc = vbus_devclass_find(type);
	if (!dc)
		return -ENOENT;

	ret = dc->ops->create(dc, &dev);
	if (ret < 0)
		goto out;

	_dev = kzalloc(sizeof(*_dev), GFP_KERNEL);
	if (!_dev) {
		ret = -ENOMEM;
		goto out;
	}

	mutex_lock(&vadmin->lock);

	namelen = snprintf(_dev->name, sizeof(_dev->name), "%s-%s-%ld",
			   vadmin->name, type, vadmin->devindex++);

	if (args->name.ptr) {

		if (args->name.len <= namelen) {
			args->name.len = namelen+1;
			ret = -EINVAL;
			goto out;
		}

		if (!access_ok(VERIFY_WRITE, args->name.ptr, namelen)) {
			ret = -EFAULT;
			goto out;
		}
	}

	ret = vbus_devshell_create(_dev->name, &ds);
	if (ret < 0)
		goto out;

	_dev->ds  = ds;
	ds->dev   = dev;
	ds->dc    = dc;
	dev->kobj = &ds->kobj;

	ret = vbus_devshell_type_set(ds);
	if (ret < 0)
		goto out;

	ret = dev->ops->bus_connect(dev, vadmin->bus);
	if (ret < 0)
		goto out;

	list_add_tail(&_dev->list, &vadmin->devs);

	if (args->name.ptr) {
		ret = copy_to_user((void *)args->name.ptr, _dev->name,
				   namelen+1);
		if (ret) {
			ret = -EFAULT;
			goto out;
		}

		args->name.len = namelen;
	}

	mutex_unlock(&vadmin->lock);

	return 0;

out:
	mutex_unlock(&vadmin->lock);

	if (ds)
		kobject_put(&ds->kobj);
	else if (dev)
		dev->ops->release(dev);

	if (dc)
		vbus_devclass_put(dc);

	return ret;
}

static long
vbus_admin_chardev_ioctl(struct file *filp, unsigned int ioctl,
			 unsigned long arg)
{
	struct vbus_admin *vadmin = filp->private_data;

	switch (ioctl) {
	case VBUS_ADMIN_NEGOTIATE:
		return _negotiate_ioctl(vadmin,
					(struct vbus_admin_negotiate *)arg);
	case VBUS_ADMIN_DEV_CREATE:
		return _dev_create_ioctl(vadmin,
					(struct vbus_admin_dev_create *)arg);
	default:
		return -EINVAL;
	}

	return 0;
}

static int
vbus_admin_chardev_release(struct inode *inode, struct file *filp)
{
	struct vbus_admin *vadmin = filp->private_data;
	struct _device *_dev, *tmp;

	/* Unlink and release each created device */
	list_for_each_entry_safe(_dev, tmp, &vadmin->devs, list) {
		struct vbus_devshell *ds = _dev->ds;
		struct vbus_device *dev = ds->dev;

		dev->ops->bus_disconnect(dev, vadmin->bus);
		kobject_put(&ds->kobj);

		if (ds->dc)
			vbus_devclass_put(ds->dc);

		list_del(&_dev->list);
		kfree(_dev);
	}

	vbus_put(vadmin->bus);
	kfree(vadmin);

	return 0;
}

static const struct file_operations vbus_admin_chardev_ops = {
	.open           = vbus_admin_chardev_open,
	.unlocked_ioctl = vbus_admin_chardev_ioctl,
	.compat_ioctl   = vbus_admin_chardev_ioctl,
	.release        = vbus_admin_chardev_release,
};

static struct miscdevice vbus_admin_chardev = {
	MISC_DYNAMIC_MINOR,
	"vbus-admin",
	&vbus_admin_chardev_ops,
};

static int __init
vbus_admin_init(void)
{
	return misc_register(&vbus_admin_chardev);
}

static void __exit
vbus_admin_cleanup(void)
{
	misc_deregister(&vbus_admin_chardev);
}

module_init(vbus_admin_init);
module_exit(vbus_admin_cleanup);
