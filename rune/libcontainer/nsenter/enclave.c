#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <linux/limits.h>

/* Defined in nsexec.c. */

#define PANIC   "panic"
#define FATAL   "fatal"
#define ERROR   "error"
#define WARNING "warning"
#define INFO    "info"
#define DEBUG   "debug"

void write_log_with_info(const char *level, const char *function,
			 int line, const char *format, ...);

#define write_log(level, fmt, ...) \
	write_log_with_info((level), __FUNCTION__, __LINE__, (fmt), ##__VA_ARGS__)

void *fptr_pal_get_version;
void *fptr_pal_init;
void *fptr_pal_exec;
void *fptr_pal_kill;
void *fptr_pal_destroy;
void *fptr_pal_create_process;

bool enclave_configured(void)
{
	const char *p = getenv("_LIBENCLAVE_PAL_PATH");
	if (p == NULL || *p == '\0')
		return false;
	return true;
}

bool is_init_runelet(void)
{
	const char *type = getenv("_LIBCONTAINER_INITTYPE");
        if (type == NULL || *type == '\0')
                return false;
	return !strcmp(type, "standard");
}

int load_enclave_runtime(void)
{
	char *pal_path;
	void *dl;

	pal_path = getenv("_LIBENCLAVE_PAL_PATH");
	if (pal_path == NULL || *pal_path == '\0') {
		write_log(ERROR, "_LIBENCLAVE_PAL_PATH should not be empty");
		/* set errno correctly, make bail() work better */
		errno = EINVAL;
		return -1;
	}

	write_log(DEBUG, "_LIBENCLAVE_PAL_PATH=%s", pal_path);

	dl = dlopen(pal_path, RTLD_NOW);
	if (dl == NULL) {
		write_log(ERROR, "failed to dlopen(): %s", dlerror());
		return -1;
	}

#define DLSYM(fn)								\
	do {									\
		fptr_pal_ ## fn = dlsym(dl, "pal_" #fn);				\
		write_log(DEBUG, "dlsym(%s)=%p", "pal_" #fn, fptr_pal_ ## fn);	\
	} while (0)

	DLSYM(get_version);
	DLSYM(init);
	DLSYM(create_process);
	DLSYM(exec);
	DLSYM(kill);
	DLSYM(destroy);
#undef DLSYM

	return 0;
}
