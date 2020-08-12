#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>
#include <sys/stat.h>
#include "liberpal-skeleton.h"
#include "sgx_call.h"
#include "defines.h"

int pal_get_version(void)
{
	return 3;
}

int pal_init(pal_attr_t *attr)
{
	return __pal_init(attr);
}

int pal_create_process(pal_create_process_args *args)
{
	if (!is_oot_driver) {
		return __pal_create_process(args);
	}

	return 0;
}

int pal_exec(pal_exec_args *attr)
{
	return wait4child(attr);
}

int pal_get_local_report(void *targetinfo, int targetinfo_len, void *report, int* report_len) {
	return __pal_get_local_report(targetinfo, targetinfo_len, report, report_len);
}

int pal_kill(int pid, int sig)
{
	return __pal_kill(pid, sig);
}

int pal_destroy(void)
{
	return __pal_destory();
}
