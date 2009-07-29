/*
 * Copyright 2009 Novell.  All Rights Reserved.
 *
 * Virtual-Bus
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

#ifndef _LINUX_VBUS_H
#define _LINUX_VBUS_H

#ifdef CONFIG_VBUS

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/vbus_device.h>
#include <linux/notifier.h>

struct vbus;
struct task_struct;

/**
 * vbus_associate() - associate a task with a vbus
 * @vbus:      The bus context to associate with
 * @p:         The task to associate
 *
 * This function adds a task as a member of a vbus.  Tasks must be members
 * of a bus before they are allowed to use its resources.  Tasks may only
 * associate with a single bus at a time.
 *
 * Note: children inherit any association present at fork().
 *
 * Returns: success = 0, <0 = ERRNO
 *
 **/
int vbus_associate(struct vbus *vbus, struct task_struct *p);

/**
 * vbus_disassociate() - disassociate a task with a vbus
 * @vbus:      The bus context to disassociate with
 * @p:         The task to disassociate
 *
 * This function removes a task as a member of a vbus.
 *
 * Returns: success = 0, <0 = ERRNO
 *
 **/
int vbus_disassociate(struct vbus *vbus, struct task_struct *p);

struct vbus *vbus_get(struct vbus *);
void vbus_put(struct vbus *);

/**
 * vbus_name() - returns the name of a bus
 * @vbus:      The bus context
 *
 * Returns: (char *) name of bus
 *
 **/
const char *vbus_name(struct vbus *vbus);

/**
 * vbus_find() - retreives a vbus pointer from its name
 * @name:      The name of the bus to find
 *
 * Returns: NULL = failure, non-null = (vbus *)bus-pointer
 *
 **/
struct vbus *vbus_find(const char *name);

/**
 * task_vbus_get() - retreives an associated vbus pointer from a task
 * @p:         The task context
 *
 * Safely retreives a pointer to an associated (if any) vbus from a task
 *
 * Returns: NULL = no association, non-null = (vbus *)bus-pointer
 *
 **/
static inline struct vbus *task_vbus_get(struct task_struct *p)
{
	struct vbus *vbus;

	rcu_read_lock();
	vbus = rcu_dereference(p->vbus);
	if (vbus)
		vbus_get(vbus);
	rcu_read_unlock();

	return vbus;
}

/**
 * fork_vbus() - Helper function to handle associated task forking
 * @p:         The task context
 *
 **/
static inline void fork_vbus(struct task_struct *p)
{
	struct vbus *vbus = task_vbus_get(p);

	if (vbus) {
		BUG_ON(vbus_associate(vbus, p) < 0);
		vbus_put(vbus);
	}
}

/**
 * task_vbus_disassociate() - Helper function to handle disassociating tasks
 * @p:         The task context
 *
 **/
static inline void task_vbus_disassociate(struct task_struct *p)
{
	struct vbus *vbus = task_vbus_get(p);

	if (vbus) {
		rcu_assign_pointer(p->vbus, NULL);
		synchronize_rcu();

		vbus_disassociate(vbus, p);
		vbus_put(vbus);
	}
}

enum {
	VBUS_EVENT_DEVADD,
	VBUS_EVENT_DEVDROP,
};

struct vbus_event_devadd {
	const char   *type;
	unsigned long id;
};

int vbus_notifier_register(struct vbus *vbus, struct notifier_block *nb);
int vbus_notifier_unregister(struct vbus *vbus, struct notifier_block *nb);


#else /* CONFIG_VBUS */

#define fork_vbus(p) do { } while (0)
#define task_vbus_disassociate(p) do { } while (0)

#endif /* CONFIG_VBUS */

#endif /* _LINUX_VBUS_H */
