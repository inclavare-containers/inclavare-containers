/* *INDENT-OFF* */
#ifndef LIBERPAL_SKELETON_H
#define LIBERPAL_SKELETON_H
/* *INDENT-ON* */

#include <stdbool.h>
#include <stdint.h>

#define	PAGE_SIZE	4096
#define	IMAGE		"encl.bin"
#define	SIGSTRUCT	"encl.ss"

extern struct sgx_secs secs;
extern bool is_oot_driver;
extern bool debugging;
extern int enclave_fd;
extern void *tcs_busy;
extern bool initialized;
extern bool backend_kvm;
extern struct kvm *kvm_vm;

typedef struct {
	const char *args;
	const char *log_level;
} pal_attr_v1_t;

typedef struct {
	pal_attr_v1_t attr_v1;
	int fd;
	uint64_t addr;
} pal_attr_v3_t;

typedef struct {
	int stdin, stdout, stderr;
} pal_stdio_fds;

typedef struct {
	char *path;
	char **argv;
	char **env;
	pal_stdio_fds *stdio;
	int *pid;
} pal_create_process_args;

typedef struct {
	int pid;
	int *exit_value;
} pal_exec_args;

struct enclave_info {
	uint64_t mmap_base;
	uint64_t mmap_size;
	uint64_t encl_base;
	uint64_t encl_size;
	uint64_t encl_offset;
};

int encl_init(struct enclave_info *encl_info);
void parse_args(const char *args);
/* *INDENT-OFF* */
int __pal_init_v1(pal_attr_v1_t *attr);
int __pal_exec(char *path, char *argv[], pal_stdio_fds *stdio, int *exit_code);
int __pal_create_process(pal_create_process_args *args);
int wait4child(pal_exec_args *attr);
/* *INDENT-ON* */
int __pal_get_local_report(void *targetinfo, int targetinfo_len,
			   void *report, int *report_len);
int __pal_kill(int pid, int sig);
int __pal_destroy(void);

/* *INDENT-OFF* */
#endif
/* *INDENT-ON* */
