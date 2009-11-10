#ifndef _MACVLAN_H
#define _MACVLAN_H

#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/list.h>

#define MACVLAN_HASH_SIZE	(1 << BITS_PER_BYTE)

struct macvlan_port {
	struct net_device	*dev;
	struct hlist_head	vlan_hash[MACVLAN_HASH_SIZE];
	struct list_head	vlans;
};

struct macvlan_dev {
	struct net_device	*dev;
	struct list_head	list;
	struct hlist_node	hlist;
	struct macvlan_port	*port;
	struct net_device	*lowerdev;

	int (*receive)(struct sk_buff *skb);
};

extern int macvlan_start_xmit(struct sk_buff *skb, struct net_device *dev);
extern int macvlan_link_lowerdev(struct net_device *dev,
						  struct net_device *lowerdev);

extern void macvlan_unlink_lowerdev(struct net_device *dev);

extern void macvlan_transfer_operstate(struct net_device *dev);

extern void macvlan_setup(struct net_device *dev);

extern int macvlan_validate(struct nlattr *tb[], struct nlattr *data[]);

extern int macvlan_newlink(struct net_device *dev,
		struct nlattr *tb[], struct nlattr *data[]);

extern void macvlan_dellink(struct net_device *dev);

#endif /* _MACVLAN_H */
