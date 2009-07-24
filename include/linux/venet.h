/*
 * Copyright 2009 Novell.  All Rights Reserved.
 *
 * Virtual-Ethernet adapter
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

#ifndef _LINUX_VENET_H
#define _LINUX_VENET_H

#include <linux/types.h>

#define VENET_VERSION 1

#define VENET_TYPE "virtual-ethernet"

#define VENET_QUEUE_RX 0
#define VENET_QUEUE_TX 1

struct venet_capabilities {
	__u32 gid;
	__u32 bits;
};

/* CAPABILITIES-GROUP 0 */
/* #define VENET_CAP_FOO    0   (No capabilities defined yet, for now) */

#define VENET_FUNC_LINKUP   0
#define VENET_FUNC_LINKDOWN 1
#define VENET_FUNC_MACQUERY 2
#define VENET_FUNC_NEGCAP   3 /* negotiate capabilities */
#define VENET_FUNC_FLUSHRX  4

#endif /* _LINUX_VENET_H */
