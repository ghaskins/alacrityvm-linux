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

#ifndef __VBUS_H__
#define __VBUS_H__

#include <linux/configfs.h>
#include <linux/rbtree.h>
#include <linux/mutex.h>
#include <linux/kobject.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kref.h>

#include "map.h"

#define VBUS_VERSION 1

struct vbus_subdir {
	struct map     map;
	struct kobject kobj;
};

struct vbus {
	struct {
		struct config_group group;
		struct config_group perms;
		struct config_group *defgroups[2];
	} ci;

	struct kref kref;
	struct mutex lock;
	struct kobject kobj;
	struct vbus_subdir devices;
	struct vbus_subdir members;
	unsigned long next_id;
	struct rb_node node;
};

struct vbus_member {
	struct rb_node      node;
	struct task_struct *tsk;
	struct vbus        *vbus;
	struct kobject      kobj;
};

struct vbus_devclasses {
	struct kobject *kobj;
	struct map map;
};

struct vbus_buses {
	struct config_group ci_group;
	struct map map;
	struct kobject *kobj;
};

struct vbus_devshell {
	struct config_group ci_group;
	struct vbus_device *dev;
	struct vbus_devclass *dc;
	struct kobject kobj;
	struct kobject intfs;
};

struct vbus_devices {
	struct config_group ci_group;
	struct kobject *kobj;
};

struct vbus_root {
	struct {
		struct configfs_subsystem subsys;
		struct config_group      *defgroups[3];
	} ci;

	struct mutex            lock;
	struct kobject         *kobj;
	struct vbus_devclasses  devclasses;
	struct vbus_buses       buses;
	struct vbus_devices     devices;
};

extern struct vbus_root vbus_root;
extern struct sysfs_ops vbus_dev_attr_ops;

int vbus_config_init(void);
int vbus_devclass_init(void);

int vbus_create(const char *name, struct vbus **bus);

int vbus_devshell_create(const char *name, struct vbus_devshell **ds);
struct vbus_devclass *vbus_devclass_find(const char *name);
int vbus_devshell_type_set(struct vbus_devshell *ds);

long vbus_interface_find(struct vbus *vbus,
			 unsigned long id,
			 struct vbus_device_interface **intf);

#endif /* __VBUS_H__ */
