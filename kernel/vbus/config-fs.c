#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <linux/vbus.h>
#include <linux/configfs.h>

#include "vbus.h"

static struct config_item_type perms_type = {
	.ct_owner	= THIS_MODULE,
};

static struct vbus *to_vbus(struct config_group *group)
{
	return group ? container_of(group, struct vbus, ci.group) : NULL;
}

static struct vbus *item_to_vbus(struct config_item *item)
{
	return to_vbus(to_config_group(item));
}

static struct vbus_devshell *to_devshell(struct config_group *group)
{
	return group ? container_of(group, struct vbus_devshell, ci_group)
		: NULL;
}

static struct vbus_devshell *to_vbus_devshell(struct config_item *item)
{
	return to_devshell(to_config_group(item));
}

static int
device_bus_connect(struct config_item *src, struct config_item *target)
{
	struct vbus *vbus = item_to_vbus(src);
	struct vbus_devshell *ds;

	/* We only allow connections to devices */
	if (target->ci_parent != &vbus_root.devices.ci_group.cg_item)
		return -EINVAL;

	ds = to_vbus_devshell(target);
	BUG_ON(!ds);

	if (!ds->dev)
		return -EINVAL;

	return ds->dev->ops->bus_connect(ds->dev, vbus);
}

static int
device_bus_disconnect(struct config_item *src, struct config_item *target)
{
	struct vbus *vbus = item_to_vbus(src);
	struct vbus_devshell *ds;

	ds = to_vbus_devshell(target);
	BUG_ON(!ds);

	if (!ds->dev)
		return -EINVAL;

	return ds->dev->ops->bus_disconnect(ds->dev, vbus);
}

static struct configfs_item_operations bus_ops = {
	.allow_link = device_bus_connect,
	.drop_link = device_bus_disconnect,
};

static struct config_item_type bus_type = {
	.ct_item_ops    = &bus_ops,
	.ct_owner	= THIS_MODULE,
};

static struct config_group *bus_create(struct config_group *group,
				       const char *name)
{
	struct vbus *bus = NULL;
	int ret;

	ret = vbus_create(name, &bus);
	if (ret < 0)
		return ERR_PTR(ret);

	config_group_init_type_name(&bus->ci.group, name, &bus_type);
	bus->ci.group.default_groups = bus->ci.defgroups;
	bus->ci.group.default_groups[0] = &bus->ci.perms;
	bus->ci.group.default_groups[1] = NULL;

	config_group_init_type_name(&bus->ci.perms, "perms", &perms_type);

	return &bus->ci.group;
}

static void bus_destroy(struct config_group *group, struct config_item *item)
{
	struct vbus *vbus = item_to_vbus(item);

	vbus_put(vbus);
}

static struct configfs_group_operations buses_ops = {
	.make_group	= bus_create,
	.drop_item      = bus_destroy,
};

static struct config_item_type buses_type = {
	.ct_group_ops	= &buses_ops,
	.ct_owner	= THIS_MODULE,
};

CONFIGFS_ATTR_STRUCT(vbus_devshell);
#define DEVSHELL_ATTR(_name, _mode, _show, _store)	\
struct vbus_devshell_attribute vbus_devshell_attr_##_name = \
    __CONFIGFS_ATTR(_name, _mode, _show, _store)

static ssize_t devshell_type_read(struct vbus_devshell *ds, char *page)
{
	if (ds->dev)
		return sprintf(page, "%s\n", ds->dev->type);
	else
		return sprintf(page, "\n");
}

static ssize_t devshell_type_write(struct vbus_devshell *ds, const char *page,
				   size_t count)
{
	struct vbus_devclass *dc;
	struct vbus_device *dev;
	char name[256];
	int ret;

	/*
	 * The device-type can only be set once, and then it is permenent.
	 * The admin should delete the device-shell if they want to create
	 * a new type
	 */
	if (ds->dev)
		return -EINVAL;

	if (count > sizeof(name))
		return -EINVAL;

	strcpy(name, page);
	if (name[count-1] == '\n')
		name[count-1] = 0;

	dc = vbus_devclass_find(name);
	if (!dc)
		return -ENOENT;

	ret = dc->ops->create(dc, &dev);
	if (ret < 0) {
		vbus_devclass_put(dc);
		return ret;
	}

	ds->dev = dev;
	ds->dc = dc;
	dev->kobj = &ds->kobj;

	ret = vbus_devshell_type_set(ds);
	if (ret < 0) {
		vbus_devclass_put(dc);
		return ret;
	}

	return count;
}

static DEVSHELL_ATTR(type, S_IRUGO | S_IWUSR, devshell_type_read,
	    devshell_type_write);

static struct configfs_attribute *devshell_attrs[] = {
	&vbus_devshell_attr_type.attr,
	NULL,
};

CONFIGFS_ATTR_OPS(vbus_devshell);
static struct configfs_item_operations devshell_item_ops = {
	.show_attribute		= vbus_devshell_attr_show,
	.store_attribute	= vbus_devshell_attr_store,
};

static struct config_item_type devshell_type = {
	.ct_item_ops	= &devshell_item_ops,
	.ct_attrs	= devshell_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct config_group *devshell_create(struct config_group *group,
					    const char *name)
{
	struct vbus_devshell *ds = NULL;
	int ret;

	ret = vbus_devshell_create(name, &ds);
	if (ret < 0)
		return ERR_PTR(ret);

	config_group_init_type_name(&ds->ci_group, name, &devshell_type);

	return &ds->ci_group;
}

static void devshell_release(struct config_group *group,
			     struct config_item *item)
{
	struct vbus_devshell *ds = to_vbus_devshell(item);

	kobject_put(&ds->kobj);

	if (ds->dc)
		vbus_devclass_put(ds->dc);
}

static struct configfs_group_operations devices_ops = {
	.make_group	= devshell_create,
	.drop_item      = devshell_release,
};

static struct config_item_type devices_type = {
	.ct_group_ops	= &devices_ops,
	.ct_owner	= THIS_MODULE,
};

static struct config_item_type root_type = {
	.ct_owner	= THIS_MODULE,
};

int __init vbus_config_init(void)
{
	int ret;
	struct configfs_subsystem *subsys = &vbus_root.ci.subsys;

	config_group_init_type_name(&subsys->su_group, "vbus", &root_type);
	mutex_init(&subsys->su_mutex);

	subsys->su_group.default_groups = vbus_root.ci.defgroups;
	subsys->su_group.default_groups[0] = &vbus_root.buses.ci_group;
	subsys->su_group.default_groups[1] = &vbus_root.devices.ci_group;
	subsys->su_group.default_groups[2] = NULL;

	config_group_init_type_name(&vbus_root.buses.ci_group,
				    "instances", &buses_type);

	config_group_init_type_name(&vbus_root.devices.ci_group,
				    "devices", &devices_type);

	ret = configfs_register_subsystem(subsys);
	if (ret) {
		printk(KERN_ERR "Error %d while registering subsystem %s\n",
		       ret,
		       subsys->su_group.cg_item.ci_namebuf);
		goto out_unregister;
	}

	return 0;

out_unregister:
	configfs_unregister_subsystem(subsys);

	return ret;
}

