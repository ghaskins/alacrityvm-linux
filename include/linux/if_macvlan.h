#ifndef _LINUX_IF_MACVLAN_H
#define _LINUX_IF_MACVLAN_H

#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/list.h>

#define MACVLAN_HASH_SIZE       (1 << BITS_PER_BYTE)

struct macvlan_port {
        struct net_device       *dev;
        struct hlist_head       vlan_hash[MACVLAN_HASH_SIZE];
        struct list_head        vlans;
};

/**
 *      struct macvlan_rx_stats - MACVLAN percpu rx stats
 *      @rx_packets: number of received packets
 *      @rx_bytes: number of received bytes
 *      @multicast: number of received multicast packets
 *      @rx_errors: number of errors
 */
struct macvlan_rx_stats {
        unsigned long rx_packets;
        unsigned long rx_bytes;
        unsigned long multicast;
        unsigned long rx_errors;
};

struct macvlan_dev {
        struct net_device       *dev;
        struct list_head        list;
        struct hlist_node       hlist;
        struct macvlan_port     *port;
        struct net_device       *lowerdev;
        struct macvlan_rx_stats *rx_stats;
        enum macvlan_mode       mode;
        int (*receive)(struct sk_buff *skb);
};

extern netdev_tx_t macvlan_start_xmit(struct sk_buff *skb, struct net_device *dev);

extern void macvlan_setup(struct net_device *dev);

extern int macvlan_validate(struct nlattr *tb[], struct nlattr *data[]);

extern int macvlan_newlink(struct net *src_net, struct net_device *dev,
			   struct nlattr *tb[], struct nlattr *data[]);

extern void macvlan_dellink(struct net_device *dev, struct list_head *head);

extern struct sk_buff *(*macvlan_handle_frame_hook)(struct sk_buff *);

#endif /* _LINUX_IF_MACVLAN_H */
