#ifndef MYHEADER_H
#define MYHEADER_H
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#define MAX_PENDING_JOBS 10
#define BUFFER_SIZE 1024

extern struct nf_hook_ops duplicate_packet_ops;
extern struct workqueue_struct * packet_wq;

#endif