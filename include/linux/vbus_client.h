/*
 * Copyright 2009 Novell.  All Rights Reserved.
 *
 * Virtual-Bus - Client interface
 *
 * We expect to have various types of connection-clients (e.g. userspace,
 * kvm, etc).  Each client will be connecting from some environment outside
 * of the kernel, and therefore will not have direct access to the API as
 * presented in ./linux/vbus.h.  There will undoubtedly be some parameter
 * marshalling that must occur, as well as common patterns for the handling
 * of those marshalled parameters (e.g. translating a handle into a pointer,
 * etc).
 *
 * Therefore this "client" API is provided to simplify the development
 * of any clients.  Of course, a client is free to bypass this API entirely
 * and communicate with the direct VBUS API if desired.
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

#ifndef _LINUX_VBUS_CLIENT_H
#define _LINUX_VBUS_CLIENT_H

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/kref.h>
#include <linux/compiler.h>

struct vbus_client;

struct vbus_client_ops {
	int (*deviceopen)(struct vbus_client *client,  struct vbus_memctx *ctx,
			  __u32 devid, __u32 version, __u64 *devh);
	int (*deviceclose)(struct vbus_client *client, __u64 devh);
	int (*devicecall)(struct vbus_client *client,
			  __u64 devh, __u32 func,
			  void *data, __u32 len, __u32 flags);
	int (*deviceshm)(struct vbus_client *client,
			 __u64 devh, __u32 id,
			 struct vbus_shm *shm, struct shm_signal *signal,
			 __u32 flags);
	void (*release)(struct vbus_client *client);
};

struct vbus_client {
	struct kref kref;
	struct vbus_client_ops *ops;
};

static inline void vbus_client_get(struct vbus_client *client)
{
	kref_get(&client->kref);
}

static inline void _vbus_client_release(struct kref *kref)
{
	struct vbus_client *client;

	client = container_of(kref, struct vbus_client, kref);
	client->ops->release(client);
}

static inline void vbus_client_put(struct vbus_client *client)
{
	kref_put(&client->kref, _vbus_client_release);
}

struct vbus_client *vbus_client_attach(struct vbus *bus);

extern struct vbus_memctx *current_memctx;
struct vbus_memctx *task_memctx_alloc(struct task_struct *task);

#endif /* __KERNEL__ */

#endif /* _LINUX_VBUS_CLIENT_H */
