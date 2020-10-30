#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include "liberpal-skeleton.h"
#include "../kvmtool/libvmm.h"

int pal_get_version(void)
{
	return 2;
}

/* *INDENT-OFF* */
int pal_init(pal_attr_v1_t *attr)
{
	return __pal_init_v1(attr);
}

int pal_create_process(pal_create_process_args *args)
{
	return __pal_create_process(args);
}

int pal_exec(pal_exec_args *attr)
{
	if (backend_kvm)
		return libvmm_vm_run(kvm_vm);

	return wait4child(attr);
}
/* *INDENT-ON* */

int pal_kill(int pid, int sig)
{
	return __pal_kill(pid, sig);
}

int pal_destroy(void)
{
	return __pal_destroy();
}
