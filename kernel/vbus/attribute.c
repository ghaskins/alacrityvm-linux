#include <linux/vbus.h>
#include <linux/uaccess.h>
#include <linux/kobject.h>
#include <linux/kallsyms.h>

#include "vbus.h"

static struct vbus_device_attribute *to_vattr(struct attribute *attr)
{
	return container_of(attr, struct vbus_device_attribute, attr);
}

static struct vbus_devshell *to_devshell(struct kobject *kobj)
{
	return container_of(kobj, struct vbus_devshell, kobj);
}

static ssize_t _dev_attr_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct vbus_devshell *ds = to_devshell(kobj);
	struct vbus_device_attribute *vattr = to_vattr(attr);
	ssize_t ret = -EIO;

	if (vattr->show)
		ret = vattr->show(ds->dev, vattr, buf);

	if (ret >= (ssize_t)PAGE_SIZE) {
		print_symbol("vbus_attr_show: %s returned bad count\n",
				(unsigned long)vattr->show);
	}

	return ret;
}

static ssize_t _dev_attr_store(struct kobject *kobj, struct attribute *attr,
			       const char *buf, size_t count)
{
	struct vbus_devshell *ds = to_devshell(kobj);
	struct vbus_device_attribute *vattr = to_vattr(attr);
	ssize_t ret = -EIO;

	if (vattr->store)
		ret = vattr->store(ds->dev, vattr, buf, count);

	return ret;
}

struct sysfs_ops vbus_dev_attr_ops = {
	.show	= _dev_attr_show,
	.store	= _dev_attr_store,
};
