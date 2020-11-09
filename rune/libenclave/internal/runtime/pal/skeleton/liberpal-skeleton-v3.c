#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "liberpal-skeleton.h"
#include "sgx_call.h"
#include "defines.h"

int pal_get_version(void)
{
	return 3;
}

/* *INDENT-OFF* */
int pal_init(pal_attr_v3_t *attr)
{
	int ret;
	char *result;

	parse_args(attr->attr_v1.args);

	tcs_busy = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (tcs_busy == MAP_FAILED)
		return -EINVAL;
	*(uint8_t *) tcs_busy = 0;

	if (attr->fd != -1) {
		enclave_fd = attr->fd;
		secs.base = attr->addr;
		goto out;
	}

	ret = encl_init();
	if (ret != 0)
		return ret;

out:
	result = malloc(sizeof(INIT_HELLO));
	if (!result) {
		fprintf(stderr, "fail to malloc INIT_HELLO\n");
		return -ENOMEM;
	}
	ret = SGX_ENTER_1_ARG(ECALL_INIT, (void *) secs.base, result);
	if (ret) {
		fprintf(stderr, "failed to initialize enclave\n");
		free(result);
		return ret;
	}
	puts(result);
	free(result);

	initialized = true;

	return 0;
}

int pal_create_process(pal_create_process_args *args)
{
	return __pal_create_process(args);
}

int pal_exec(pal_exec_args *attr)
{
	return wait4child(attr);
}
/* *INDENT-ON* */

int pal_get_local_report(void *targetinfo, int targetinfo_len, void *report,
			 int *report_len)
{
	return __pal_get_local_report(targetinfo, targetinfo_len, report,
				      report_len);
}

int pal_kill(int pid, int sig)
{
	return __pal_kill(pid, sig);
}

int pal_destroy(void)
{
	return __pal_destroy();
}
