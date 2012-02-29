
#include <linux/errno.h>

#include "map.h"

void map_init(struct map *map, struct map_ops *ops)
{
	map->root = RB_ROOT;
	map->ops = ops;
}

int map_add(struct map *map, struct rb_node *node)
{
	int		ret = 0;
	struct rb_root *root;
	struct rb_node **new, *parent = NULL;

	root = &map->root;
	new  = &(root->rb_node);

	/* Figure out where to put new node */
	while (*new) {
		int val;

		parent = *new;

		val = map->ops->item_compare(node, *new);
		if (val < 0)
			new = &((*new)->rb_left);
		else if (val > 0)
			new = &((*new)->rb_right);
		else {
			ret = -EEXIST;
			break;
		}
	}

	if (!ret) {
		/* Add new node and rebalance tree. */
		rb_link_node(node, parent, new);
		rb_insert_color(node, root);
	}

	return ret;
}

struct rb_node *map_find(struct map *map, const void *key)
{
	struct rb_node *node;

	node = map->root.rb_node;

	while (node) {
		int val;

		val = map->ops->key_compare(key, node);
		if (val < 0)
			node = node->rb_left;
		else if (val > 0)
			node = node->rb_right;
		else
			break;
	}

	return node;
}

void map_del(struct map *map, struct rb_node *node)
{
	rb_erase(node, &map->root);
}

