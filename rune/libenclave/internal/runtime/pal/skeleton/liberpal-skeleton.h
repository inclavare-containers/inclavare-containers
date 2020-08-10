#ifndef LIBERPAL_SKELETON_H
#define LIBERPAL_SKELETON_H

typedef struct {
        const char *args;
        const char *log_level;
} pal_attr_t;

typedef struct {
        int stdin, stdout, stderr;
} pal_stdio_fds;

int __pal_init(pal_attr_t *attr);
int __pal_exec(char *path, char *argv[], pal_stdio_fds *stdio, int *exit_code);
int __pal_destory(void);

#endif
