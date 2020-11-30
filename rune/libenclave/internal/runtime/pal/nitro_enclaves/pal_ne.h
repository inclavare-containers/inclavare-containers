/* *INDENT-OFF* */
#ifndef PAL_NE_H
#define PAL_NE_H
/* *INDENT-ON* */

#define PAL_VERSION 2

struct pal_attr_t {
	const char *args;;
	const char *log_level;
};

struct pal_stdio_fds {
	int stdin, stdout, stderr;
};

struct pal_create_process_args {
	const char *path;
	const char **argv;
	const char **env;
	const struct pal_stdio_fds *stdio;
	int *pid;
};

struct pal_exec_args {
	int pid;
	int *exit_value;
};

struct pal_kill_args {
	int pid;
	int sig;
};

/* *INDENT-OFF* */
#endif /* PAL_NE_H */
/* *INDENT-ON* */
