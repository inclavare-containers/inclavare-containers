#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#define BUFF_LEN	1024
#define DEBUG_ARGS	"debug"

static const unsigned int skeleton_pal_version = 1;

static bool initialized = false;
static bool debug = false;

struct pal_attr_t {
	const char *args;
	const char *log_level;
};

struct pal_stdio_fds {
	int stdin, stdout, stderr;
};

int skeleton_pal_init(struct pal_attr_t *attr)
{
	if (!attr->args)
		return -ENOENT;

	char *args = (char *)attr->args;
	while ((args = strtok(args, " "))) {
		if (!strcmp(args, DEBUG_ARGS))
			debug = true;
		args = NULL;
	}

	initialized = true;

	return 0;
}

int skeleton_pal_exec(char *path, char *argv[], struct pal_stdio_fds *stdio,
		      int *exit_code)
{
	if (!path || access(path, F_OK) != 0)
		return -ENOENT;	

	if (access(path, R_OK) != 0)
		return -EACCES;

	if (!stdio)
		return -EINVAL;

	if (!exit_code)
		return -EINVAL;

	if (!initialized) {
		fprintf(stderr, "enclave runtime skeleton uninitialized yet!\n");
		return -EINVAL;
	}

	int i;

	if (debug) {
		for (i = 0; argv[i]; ++i)
			printf("argv[%d] = %s\n", i, argv[i]);
	}

	for (i = 0; i < 60; ++i) {
		sleep(1);
		if (stdio->stdout < 0 && debug) {
			printf("pal_exec running %d seconds\n", i + 1);
		} else {
			char buf[BUFF_LEN];

			ssize_t len;
			if (debug)
				len = snprintf(buf, BUFF_LEN, "pal_exec running %d seconds, "
					       "outputting to fd %d\n", i + 1, stdio->stdout);
			else
				len = snprintf(buf, BUFF_LEN, "%d", i + 1);

			ssize_t bytes = 0;
			while (bytes < len) {
				ssize_t n = write(stdio->stdout, &buf[bytes], len - bytes);
				if (n < 0) {
					if (errno == EAGAIN || errno == EINTR)
						continue;

					fprintf(stderr, "write failed\n");
					return -1;
				} else if (n == 0) {
					fprintf(stderr, "stdout is EOF\n");
					return -1;
				} else
					bytes += n;
			}
		}
	}

	return 0;
}

int skeleton_pal_destroy(void)
{
	if (!initialized) {
		fprintf(stderr, "enclave runtime skeleton uninitialized yet!\n");
		return -1;
	}

	printf("enclave runtime skeleton exits\n");
	return 0;
}
