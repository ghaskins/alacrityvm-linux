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

#ifndef __VBUS_MAP_H__
#define __VBUS_MAP_H__

#include <linux/rbtree.h>

struct map_ops {
	int (*item_compare)(struct rb_node *lhs, struct rb_node *rhs);
	int (*key_compare)(const void *key, struct rb_node *item);
};

struct map {
	struct rb_root root;
	struct map_ops *ops;
};

void map_init(struct map *map, struct map_ops *ops);
int map_add(struct map *map, struct rb_node *node);
struct rb_node *map_find(struct map *map, const void *key);
void map_del(struct map *map, struct rb_node *node);

#endif /* __VBUS_MAP_H__ */
