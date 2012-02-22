/*
 * Copyright 2012 Gregory Haskins <gregory.haskins@gmail.com>
 *
 * Virtual-Infiniband adapter
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

#ifndef _LINUX_VBIB_H
#define _LINUX_VBIB_H

#include <linux/types.h>

#define VBIB_TYPE "virtual-infiniband"
#define VBIB_HCA_ABI_VERSION 1
#define VBIB_UVERBS_ABI_VERSION 1

#define VBIB_ATTR_HWVER        1
#define VBIB_ATTR_LID          2
#define VBIB_ATTR_SMLID        3
#define VBIB_ATTR_LMC          4

struct vbib_capabilities {
	__u32 gid;
	__u32 bits;
};

struct vbib_attr {
	__u32       attr;
	__u32       len;
	aligned_u64 ptr;
};

#define VBIB_FUNC_NEGCAP      0 /* negotiate capabilities */
#define VBIB_FUNC_GET_ATTR    1

#endif /* _LINUX_VBIB_H */
