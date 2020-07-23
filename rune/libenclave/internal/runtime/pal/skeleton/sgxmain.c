#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

int pal_init(const char *args, const char *log_level);
int pal_exec(char *path, char *argv[], const char *envp[],
	     int *exit_code, int stdin, int stdout, int stderr);
int pal_destroy(void);

int main(int argc, char *argv[])
{
	int exit_code;
	int ret;

	ret = pal_init(NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "pal_init(), ret = %d\n", ret);
		return EXIT_FAILURE;
	}

	switch (fork()) {
	case -1:
		fprintf(stderr, "fork(), errno = %d\n", errno);
	default:
		return EXIT_SUCCESS;

	case 0:
		fprintf(stdout, "run in child process, pid = %d\n", (int)getpid());
	}

	ret = pal_exec(NULL, NULL, NULL, &exit_code,
			STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO);
	if (ret < 0) {
		fprintf(stderr, "pal_exec(), ret = %d\n", ret);
		return EXIT_FAILURE;
	}

	pal_destroy();

	fprintf(stdout, "pal_exec sueecess.\n");
	return EXIT_SUCCESS;
}
