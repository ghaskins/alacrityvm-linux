/*
 * Copyright 2009 Novell.  All Rights Reserved.
 *
 * Author:
 *      Gregory Haskins <ghaskins@novell.com>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/vbus.h>
#include <linux/uaccess.h>

#include "vbus.h"

static struct vbus_device_interface *kobj_to_intf(struct kobject *kobj)
{
	return container_of(kobj, struct vbus_device_interface, kobj);
}

static struct vbus_devshell *to_devshell(struct kobject *kobj)
{
	return container_of(kobj, struct vbus_devshell, kobj);
}

static void interface_release(struct kobject *kobj)
{
	struct vbus_device_interface *intf = kobj_to_intf(kobj);

	if (intf->ops->release)
		intf->ops->release(intf);
}

static struct kobj_type interface_ktype = {
	.release = interface_release,
	.sysfs_ops = &kobj_sysfs_ops,
};

static ssize_t
type_show(struct kobject *kobj, struct kobj_attribute *attr,
		  char *buf)
{
	struct vbus_device_interface *intf = kobj_to_intf(kobj);

	return snprintf(buf, PAGE_SIZE, "%s\n", intf->type);
}

static struct kobj_attribute devattr_type =
	__ATTR_RO(type);

static struct attribute *attrs[] = {
	&devattr_type.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

/*
 * Assumes dev->bus->lock is held
 */
static void _interface_unregister(struct vbus_device_interface *intf)
{
	struct vbus *vbus = intf->vbus;
	struct vbus_devshell *ds = to_devshell(intf->dev->kobj);

	map_del(&vbus->devices.map, &intf->node);
	sysfs_remove_link(&ds->intfs, intf->name);
	sysfs_remove_link(&intf->kobj, "device");
	sysfs_remove_group(&intf->kobj, &attr_group);
}

int vbus_device_interface_register(struct vbus_device *dev,
				   struct vbus *vbus,
				   struct vbus_device_interface *intf)
{
	int ret;
	struct vbus_devshell *ds = to_devshell(dev->kobj);

	mutex_lock(&vbus->lock);

	if (vbus->next_id == -1) {
		mutex_unlock(&vbus->lock);
		return -ENOSPC;
	}

	intf->id = vbus->next_id++;
	intf->dev = dev;
	intf->vbus = vbus;

	ret = map_add(&vbus->devices.map, &intf->node);
	if (ret < 0) {
		mutex_unlock(&vbus->lock);
		return ret;
	}

	kobject_init_and_add(&intf->kobj, &interface_ktype,
			     &vbus->devices.kobj, "%ld", intf->id);

	/* Create the basic attribute files associated with this kobject */
	ret = sysfs_create_group(&intf->kobj, &attr_group);
	if (ret)
		goto error;

	/* Create cross-referencing links between the device and bus */
	ret = sysfs_create_link(&intf->kobj, dev->kobj, "device");
	if (ret)
		goto error;

	ret = sysfs_create_link(&ds->intfs, &intf->kobj, intf->name);
	if (ret)
		goto error;

	mutex_unlock(&vbus->lock);

	return 0;

error:
	_interface_unregister(intf);
	mutex_unlock(&vbus->lock);

	kobject_put(&intf->kobj);

	return ret;
}
EXPORT_SYMBOL_GPL(vbus_device_interface_register);

int vbus_device_interface_unregister(struct vbus_device_interface *intf)
{
	struct vbus *vbus = intf->vbus;

	mutex_lock(&vbus->lock);
	_interface_unregister(intf);
	mutex_unlock(&vbus->lock);

	kobject_put(&intf->kobj);

	return 0;
}
EXPORT_SYMBOL_GPL(vbus_device_interface_unregister);

static struct vbus_device_interface *node_to_intf(struct rb_node *node)
{
	return node ? container_of(node, struct vbus_device_interface, node)
		: NULL;
}

static int interface_item_compare(struct rb_node *lhs, struct rb_node *rhs)
{
	struct vbus_device_interface *lintf = node_to_intf(lhs);
	struct vbus_device_interface *rintf = node_to_intf(rhs);

	return lintf->id - rintf->id;
}

static int interface_key_compare(const void *key, struct rb_node *node)
{
	struct vbus_device_interface *intf = node_to_intf(node);
	unsigned long id = *(unsigned long *)key;

	return id - intf->id;
}

static struct map_ops interface_map_ops = {
	.key_compare = &interface_key_compare,
	.item_compare = &interface_item_compare,
};

/*
 *-----------------
 * member
 *-----------------
 */

static struct vbus_member *node_to_member(struct rb_node *node)
{
	return node ? container_of(node, struct vbus_member, node) : NULL;
}

static struct vbus_member *kobj_to_member(struct kobject *kobj)
{
	return kobj ? container_of(kobj, struct vbus_member, kobj) : NULL;
}

static int member_item_compare(struct rb_node *lhs, struct rb_node *rhs)
{
	struct vbus_member *lmember = node_to_member(lhs);
	struct vbus_member *rmember = node_to_member(rhs);

	return lmember->tsk->pid - rmember->tsk->pid;
}

static int member_key_compare(const void *key, struct rb_node *node)
{
	struct vbus_member *member = node_to_member(node);
	pid_t pid = *(pid_t *)key;

	return pid - member->tsk->pid;
}

static struct map_ops member_map_ops = {
	.key_compare = &member_key_compare,
	.item_compare = &member_item_compare,
};

static void member_release(struct kobject *kobj)
{
	struct vbus_member *member = kobj_to_member(kobj);

	vbus_put(member->vbus);
	put_task_struct(member->tsk);

	kfree(member);
}

static struct kobj_type member_ktype = {
	.release = member_release,
};

int vbus_associate(struct vbus *vbus, struct task_struct *tsk)
{
	struct vbus_member *member;
	int ret;

	member = kzalloc(sizeof(struct vbus_member), GFP_KERNEL);
	if (!member)
		return -ENOMEM;

	mutex_lock(&vbus->lock);

	get_task_struct(tsk);
	vbus_get(vbus);

	member->vbus = vbus;
	member->tsk = tsk;

	ret = kobject_init_and_add(&member->kobj, &member_ktype,
				   &vbus->members.kobj,
				   "%d", tsk->pid);
	if (ret < 0)
		goto error;

	ret = map_add(&vbus->members.map, &member->node);
	if (ret < 0)
		goto error;

out:
	mutex_unlock(&vbus->lock);
	return 0;

error:
	kobject_put(&member->kobj);
	goto out;
}

int vbus_disassociate(struct vbus *vbus, struct task_struct *tsk)
{
	struct vbus_member *member;

	mutex_lock(&vbus->lock);

	member = node_to_member(map_find(&vbus->members.map, &tsk->pid));
	BUG_ON(!member);

	map_del(&vbus->members.map, &member->node);

	mutex_unlock(&vbus->lock);

	kobject_put(&member->kobj);

	return 0;
}

/*
 *-----------------
 * vbus_subdir
 *-----------------
 */

static void vbus_subdir_init(struct vbus_subdir *subdir,
			     const char *name,
			     struct kobject *parent,
			     struct kobj_type *type,
			     struct map_ops *map_ops)
{
	int ret;

	map_init(&subdir->map, map_ops);

	ret = kobject_init_and_add(&subdir->kobj, type, parent, name);
	BUG_ON(ret < 0);
}

/*
 *-----------------
 * vbus
 *-----------------
 */

static void vbus_destroy(struct kobject *kobj)
{
	struct vbus *vbus = container_of(kobj, struct vbus, kobj);

	kfree(vbus);
}

static struct kobj_type vbus_ktype = {
	.release = vbus_destroy,
};

static struct kobj_type null_ktype = {
};

int vbus_create(const char *name, struct vbus **bus)
{
	struct vbus *_bus = NULL;
	int ret;

	_bus = kzalloc(sizeof(struct vbus), GFP_KERNEL);
	if (!_bus)
		return -ENOMEM;

	kref_init(&_bus->kref);
	mutex_init(&_bus->lock);

	kobject_init_and_add(&_bus->kobj, &vbus_ktype,
			     vbus_root.buses.kobj, name);

	vbus_subdir_init(&_bus->devices, "devices", &_bus->kobj,
			 &null_ktype, &interface_map_ops);
	vbus_subdir_init(&_bus->members, "members", &_bus->kobj,
			 &null_ktype, &member_map_ops);

	_bus->next_id = 0;

	mutex_lock(&vbus_root.lock);

	ret = map_add(&vbus_root.buses.map, &_bus->node);
	BUG_ON(ret < 0);

	mutex_unlock(&vbus_root.lock);

	*bus = _bus;

	return 0;
}

static void devshell_release(struct kobject *kobj)
{
	struct vbus_devshell *ds = container_of(kobj,
						struct vbus_devshell, kobj);

	if (ds->dev) {
		if (ds->dev->attrs)
			sysfs_remove_group(&ds->kobj, ds->dev->attrs);

		if (ds->dev->ops->release)
			ds->dev->ops->release(ds->dev);
	}

	if (ds->dc)
		sysfs_remove_link(&ds->kobj, "class");

	kobject_put(&ds->intfs);
	kfree(ds);
}

static struct kobj_type devshell_ktype = {
	.release = devshell_release,
	.sysfs_ops = &vbus_dev_attr_ops,
};

static void _interfaces_init(struct vbus_devshell *ds)
{
	kobject_init_and_add(&ds->intfs, &null_ktype, &ds->kobj, "interfaces");
}

int vbus_devshell_create(const char *name, struct vbus_devshell **ds)
{
	struct vbus_devshell *_ds = NULL;

	_ds = kzalloc(sizeof(*_ds), GFP_KERNEL);
	if (!_ds)
		return -ENOMEM;

	kobject_init_and_add(&_ds->kobj, &devshell_ktype,
			     vbus_root.devices.kobj, name);

	_interfaces_init(_ds);

	*ds = _ds;

	return 0;
}

int vbus_devshell_type_set(struct vbus_devshell *ds)
{
	int ret;

	if (!ds->dev)
		return -EINVAL;

	if (!ds->dev->attrs)
		return 0;

	ret = sysfs_create_link(&ds->kobj, &ds->dc->kobj, "class");
	if (ret < 0)
		return ret;

	return sysfs_create_group(&ds->kobj, ds->dev->attrs);
}

struct vbus *vbus_get(struct vbus *vbus)
{
	if (vbus)
		kref_get(&vbus->kref);

	return vbus;
}
EXPORT_SYMBOL_GPL(vbus_get);

static void _vbus_release(struct kref *kref)
{
	struct vbus *vbus = container_of(kref, struct vbus, kref);

	kobject_put(&vbus->devices.kobj);
	kobject_put(&vbus->members.kobj);
	kobject_put(&vbus->kobj);
}

void vbus_put(struct vbus *vbus)
{
	if (!vbus)
		return;

	kref_put(&vbus->kref, _vbus_release);
}
EXPORT_SYMBOL_GPL(vbus_put);

long vbus_interface_find(struct vbus *bus,
			 unsigned long id,
			 struct vbus_device_interface **intf)
{
	struct vbus_device_interface *_intf;

	BUG_ON(!bus);

	mutex_lock(&bus->lock);

	_intf = node_to_intf(map_find(&bus->devices.map, &id));
	if (likely(_intf))
		kobject_get(&_intf->kobj);

	mutex_unlock(&bus->lock);

	if (!_intf)
		return -ENOENT;

	*intf = _intf;

	return 0;
}

const char *vbus_name(struct vbus *vbus)
{
	return vbus ? vbus->kobj.name : NULL;
}

/*
 *---------------------
 * vbus_buses
 *---------------------
 */

static struct vbus *node_to_bus(struct rb_node *node)
{
	return node ? container_of(node, struct vbus, node) : NULL;
}

static int bus_item_compare(struct rb_node *lhs, struct rb_node *rhs)
{
	struct vbus *lbus = node_to_bus(lhs);
	struct vbus *rbus = node_to_bus(rhs);

	return strcmp(lbus->kobj.name, rbus->kobj.name);
}

static int bus_key_compare(const void *key, struct rb_node *node)
{
	struct vbus *bus = node_to_bus(node);

	return strcmp(key, bus->kobj.name);
}

static struct map_ops bus_map_ops = {
	.key_compare = &bus_key_compare,
	.item_compare = &bus_item_compare,
};

struct vbus *vbus_find(const char *name)
{
	struct vbus *bus;

	mutex_lock(&vbus_root.lock);

	bus = node_to_bus(map_find(&vbus_root.buses.map, name));
	if (!bus)
		goto out;

	vbus_get(bus);

out:
	mutex_unlock(&vbus_root.lock);

	return bus;

}

struct vbus_root vbus_root;

static ssize_t version_show(struct kobject *kobj,
			struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", VBUS_VERSION);
}

static struct kobj_attribute version_attr =
	__ATTR(version, S_IRUGO, version_show, NULL);

static int __init vbus_init(void)
{
	int ret;

	mutex_init(&vbus_root.lock);

	ret = vbus_config_init();
	BUG_ON(ret < 0);

	vbus_root.kobj = kobject_create_and_add("vbus", NULL);
	BUG_ON(!vbus_root.kobj);

	ret = sysfs_create_file(vbus_root.kobj, &version_attr.attr);
	BUG_ON(ret);

	ret = vbus_devclass_init();
	BUG_ON(ret < 0);

	map_init(&vbus_root.buses.map, &bus_map_ops);
	vbus_root.buses.kobj = kobject_create_and_add("instances",
						      vbus_root.kobj);
	BUG_ON(!vbus_root.buses.kobj);

	vbus_root.devices.kobj = kobject_create_and_add("devices",
							vbus_root.kobj);
	BUG_ON(!vbus_root.devices.kobj);

	return 0;
}

late_initcall(vbus_init);


