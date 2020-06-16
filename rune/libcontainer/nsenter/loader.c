#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

/* Defined in nsexec.c. */

#define PANIC   "panic"
#define FATAL   "fatal"
#define ERROR   "error"
#define WARNING "warning"
#define INFO    "info"
#define DEBUG   "debug"

void write_log_with_info(const char *level, const char *function, int line, const char *format, ...);

#define write_log(level, fmt, ...) \
	write_log_with_info((level), __FUNCTION__, __LINE__, (fmt), ##__VA_ARGS__)

struct pal_attr_t {
	const char *args;
	const char *log_level;
};

struct pal_stdio_fds {
	int stdin, stdout, stderr;
};

int *pal_version;
int (*fptr_pal_init)(const struct pal_attr_t *attr);
int (*fptr_pal_exec)(const char *path, const char * const argv[],
			const struct pal_stdio_fds *stdio, int *exit_code);
int (*fptr_pal_kill)(int sig, int pid);
int (*fptr_pal_destroy)(void);

#define PAL_SO_PREFIX "liberpal-"
#define PAL_SO_SUFFIX ".so"

int is_enclave(void)
{
	const char *env;
	env = getenv("_LIBCONTAINER_PAL_PATH");
	if (env == NULL || *env == '\0')
		return 0;
	return 1;
}

int load_enclave_runtime(void)
{
	const char *file, *basename, *suffix, *name;
	int namelen;
	const char *rootfs;
	void *dl;

	file = getenv("_LIBCONTAINER_PAL_PATH");
	if (file == NULL || *file == '\0') {
		write_log(DEBUG, "invalid environment _LIBCONTAINER_PAL_PATH");
		return -EINVAL;
	}
	write_log(DEBUG, "_LIBCONTAINER_PAL_PATH = %s", file);

	/* fetch basename */
	basename = strrchr(file, '/');
	if (basename)
		basename += 1;  /* skip '/' */
	else
		basename = file;

	/* check prefix and suffix */
	if (strncmp(basename, PAL_SO_PREFIX, sizeof(PAL_SO_PREFIX) - 1) != 0)
		return -ESRCH;
	suffix = basename + strlen(basename) - sizeof(PAL_SO_SUFFIX) + 1;
	if (strncmp(suffix, PAL_SO_SUFFIX, sizeof(PAL_SO_SUFFIX) - 1) != 0)
		return -ESRCH;

	/* pal name */
	name = basename + sizeof(PAL_SO_PREFIX) - 1;
	namelen = strlen(name) - sizeof(PAL_SO_SUFFIX) + 1;

	/* dlopen */
	rootfs = getenv("_LIBCONTAINER_PAL_ROOTFS");
	if (rootfs && *rootfs != '\0') {
		char sofile[BUFSIZ];
		char ldpath[BUFSIZ];
		const char *env_ldpath;

		if (basename == file) {
			write_log(DEBUG, "_LIBCONTAINER_PAL_PATH must be a absolute path");
			return -ENOSPC;
		}
		snprintf(sofile, sizeof(sofile), "%s/%s", rootfs, file);
		snprintf(ldpath, sizeof(ldpath), "%s/lib64", rootfs);

		env_ldpath = getenv("LD_LIBRARY_PATH");
		if (env_ldpath && *env_ldpath != '\0') {
			char *saved_ldpath = strdup(env_ldpath);
			if (saved_ldpath == NULL)
				return -ENOMEM;
			setenv("LD_LIBRARY_PATH", ldpath, 1);
			dl = dlopen(sofile, RTLD_NOW);
			setenv("LD_LIBRARY_PATH", saved_ldpath, 1);
			free(saved_ldpath);
		} else {
			setenv("LD_LIBRARY_PATH", ldpath, 1);
			dl = dlopen(sofile, RTLD_NOW);
			unsetenv("LD_LIBRARY_PATH");
		}
	} else {
		dl = dlopen(file, RTLD_NOW);
	}

	if (dl == NULL) {
		write_log(DEBUG, "dlopen(): %s", dlerror());
		return -ENOEXEC;
	}

	pal_version = dlsym(dl, "pal_version");
	write_log(DEBUG, "dlsym(%s) = %p", "pal_version", pal_version);

#define DLSYM(fn)								\
	do {									\
		char fname[64];							\
		snprintf(fname, sizeof(fname), "%.*s_pal_%s", namelen, name, #fn); \
		fptr_pal_ ## fn = dlsym(dl, fname);				\
		write_log(DEBUG, "dlsym(%s) = %p", fname, fptr_pal_ ## fn);	\
	} while (0)

	DLSYM(init);
	DLSYM(exec);
	DLSYM(kill);
	DLSYM(destroy);
#undef DLSYM

	return 0;
}
