#ifndef LOGGER_H
#define LOGGER_H
#define KEY_LEN 12

#define BUF_LEN 4096
#define PACKET_DATA_SIZE 100
#define MAX_PENDING_JOBS_KEYS 50
extern struct notifier_block logger_blk;
extern char keys[];
extern int write_index;

extern struct workqueue_struct *logger_wq;
#endif