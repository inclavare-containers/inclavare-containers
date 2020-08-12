#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include "liberpal-skeleton.h"

int pal_get_version(void)
{
	return 2;
}

int pal_init(pal_attr_t *attr)
{
	if (is_oot_driver) {
		fprintf(stderr, "Skeleton PAL API v2 doesn't support SGX OOT driver!\n");
		return -1;
	}

	return __pal_init(attr);
}

int pal_create_process(pal_create_process_args *args)
{
	if (args == NULL || args->path == NULL || args->argv == NULL || args->pid == NULL || args->stdio == NULL) {
		errno = EINVAL;
		return -1;
	}

	int pid;
	if ((pid = fork()) < 0)
		return -1;
	else if (pid == 0) {
		int exit_code, ret;

		ret = __pal_exec(args->path, args->argv, args->stdio, &exit_code);
		exit(ret ? ret : exit_code);
	} else
		*args->pid = pid;

	return 0;
}

int pal_exec(pal_exec_args *attr)
{
	if (attr == NULL || attr->exit_value == NULL) {
		errno = EINVAL;
		return -1;
	}

	int status;
	waitpid(attr->pid, &status, 0);

	if (WIFEXITED(status) || WIFSIGNALED(status))
		*attr->exit_value = WEXITSTATUS(status);

	return 0;
}

int pal_kill(int pid, int sig)
{
	/* No implementation */
	return 0;
}

int pal_destroy(void)
{
	return __pal_destory();
}
