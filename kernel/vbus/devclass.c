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

#include <linux/module.h>
#include <linux/vbus.h>

#include "vbus.h"

static struct vbus_devclass *node_to_devclass(struct rb_node *node)
{
	return node ? container_of(node, struct vbus_devclass, node) : NULL;
}

static int devclass_item_compare(struct rb_node *lhs, struct rb_node *rhs)
{
	struct vbus_devclass *ldc = node_to_devclass(lhs);
	struct vbus_devclass *rdc = node_to_devclass(rhs);

	return strcmp(ldc->name, rdc->name);
}

static int devclass_key_compare(const void *key, struct rb_node *node)
{
	struct vbus_devclass *dc = node_to_devclass(node);

	return strcmp((const char *)key, dc->name);
}

static struct map_ops devclass_map_ops = {
	.key_compare = &devclass_key_compare,
	.item_compare = &devclass_item_compare,
};

int __init vbus_devclass_init(void)
{
	struct vbus_devclasses *c = &vbus_root.devclasses;

	map_init(&c->map, &devclass_map_ops);

	c->kobj = kobject_create_and_add("deviceclass", vbus_root.kobj);
	BUG_ON(!c->kobj);

	return 0;
}

static void devclass_release(struct kobject *kobj)
{
	struct vbus_devclass *dc = container_of(kobj,
						struct vbus_devclass,
						kobj);

	if (dc->ops->release)
		dc->ops->release(dc);
}

static struct kobj_type devclass_ktype = {
	.release = devclass_release,
};

int vbus_devclass_register(struct vbus_devclass *dc)
{
	int ret;

	mutex_lock(&vbus_root.lock);

	ret = map_add(&vbus_root.devclasses.map, &dc->node);
	if (ret < 0)
		goto out;

	ret = kobject_init_and_add(&dc->kobj, &devclass_ktype,
				   vbus_root.devclasses.kobj, dc->name);
	if (ret < 0) {
		map_del(&vbus_root.devclasses.map, &dc->node);
		goto out;
	}

out:
	mutex_unlock(&vbus_root.lock);

	return ret;
}
EXPORT_SYMBOL_GPL(vbus_devclass_register);

int vbus_devclass_unregister(struct vbus_devclass *dc)
{
	mutex_lock(&vbus_root.lock);
	map_del(&vbus_root.devclasses.map, &dc->node);
	mutex_unlock(&vbus_root.lock);

	kobject_put(&dc->kobj);

	return 0;
}
EXPORT_SYMBOL_GPL(vbus_devclass_unregister);

struct vbus_devclass *vbus_devclass_find(const char *name)
{
	struct vbus_devclass *dev;

	mutex_lock(&vbus_root.lock);
	dev = node_to_devclass(map_find(&vbus_root.devclasses.map, name));
	if (dev)
		dev = vbus_devclass_get(dev);
	mutex_unlock(&vbus_root.lock);

	return dev;
}
