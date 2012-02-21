/*
 * Copyright 2009 Novell, Gregory Haskins.  All Rights Reserved.
 * Copyright 2012 Gregory Haskins <gregory.haskins@gmail.com>
 *
 * Virtual-Bus Administrative Interface
 *
 * Author:
 *      Gregory Haskins <gregory.haskins@gmail.com>
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

#ifndef _LINUX_VBUS_ADMIN_H
#define _LINUX_VBUS_ADMIN_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define VBUS_ADMIN_MAGIC 0xdf39ab56
#define VBUS_ADMIN_VERSION 1

struct vbus_admin_negotiate {
	__u32 magic;
	__u32 version;
	__u64 capabilities;
};

struct vbus_admin_userbuf {
	__u64 ptr;
	__u32 len;
};

struct vbus_admin_dev_create {
	__u32                     flags;     /* in */
	__u64                     type;      /* char* in */
	struct vbus_admin_userbuf name;      /* char* out */
	__u8                      pad[36];
};

#define VBUS_ADMIN_IOCTL_MAGIC 'V'

#define VBUS_ADMIN_NEGOTIATE \
  _IOWR(VBUS_ADMIN_IOCTL_MAGIC, 0x00, struct vbus_admin_negotiate)
#define VBUS_ADMIN_DEV_CREATE \
  _IOW(VBUS_ADMIN_IOCTL_MAGIC, 0x01, struct vbus_admin_dev_create)


#endif /* _LINUX_VBUS_ADMIN_H */
