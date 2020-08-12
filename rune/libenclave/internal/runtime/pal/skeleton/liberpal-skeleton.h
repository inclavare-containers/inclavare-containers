#ifndef LIBERPAL_SKELETON_H
#define LIBERPAL_SKELETON_H

#include <stdbool.h>

extern bool is_oot_driver;
extern bool debugging;

typedef struct {
        const char *args;
        const char *log_level;
} pal_attr_t;

typedef struct {
        int stdin, stdout, stderr;
} pal_stdio_fds;

typedef struct {
        char *path;
        char **argv;
        char **env;
        pal_stdio_fds *stdio;
        int *pid;
} pal_create_process_args;

typedef struct {
	int pid;
	int *exit_value;
} pal_exec_args;

int __pal_init(pal_attr_t *attr);
int __pal_exec(char *path, char *argv[], pal_stdio_fds *stdio, int *exit_code);
int __pal_create_process(pal_create_process_args *args);
int wait4child(pal_exec_args *attr);
int __pal_get_local_report(void *targetinfo, int targetinfo_len, void *report, int* report_len);
int __pal_kill(int pid, int sig);
int __pal_destory(void);

#endif
