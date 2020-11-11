// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 25
#  include <sys/types.h>
#else
#  include <sys/sysmacros.h>
#endif
#include "defines.h"
#include "sgx_call.h"
#include "liberpal-skeleton.h"
#include "aesm.h"
#include "../kvmtool/libvmm.h"

#define SGX_REG_PAGE_FLAGS \
	(SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X)

struct sgx_secs secs;
static pal_stdio_fds pal_stdio;
bool initialized = false;
static int exit_code;
static char *sgx_dev_path;
static bool no_sgx_flc = false;
static bool enclave_debug = true;
static int wait_timeout;
uint64_t max_mmap_size = 0;
bool debugging = false;
bool is_oot_driver;
bool backend_kvm = false;
struct kvm *kvm_vm;
static const char *kvm_kernel;
static const char *kvm_rootfs;
static const char *kvm_init;
/*
 * For SGX in-tree driver, dev_fd cannot be closed until an enclave instance
 * intends to exit.
 */
int enclave_fd = -1;
void *tcs_busy;

static bool is_sgx_device(const char *dev)
{
	struct stat st;
	int rc;

	rc = stat(dev, &st);
	if (!rc) {
		if ((st.st_mode & S_IFCHR) && (major(st.st_rdev) == 10))
			return true;
	}

	return false;
}

__attribute__((constructor))
static void detect_driver_type(void)
{
	if (is_sgx_device("/dev/isgx")) {
		sgx_dev_path = "/dev/isgx";
		is_oot_driver = true;
		return;
	}

	sgx_dev_path = "/dev/sgx/enclave";
	is_oot_driver = false;
}

static uint64_t create_enclave_range(int dev_fd, uint64_t size)
{
	void *area;
	int fd;
	int flags = MAP_SHARED;

	if (is_oot_driver) {
		fd = dev_fd;
	} else {
		fd = -1;
		flags |= MAP_ANONYMOUS;
	}

	area = mmap(NULL, size * 2, PROT_NONE, flags, fd, 0);
	if (area == MAP_FAILED) {
		perror("mmap");
		return 0;
	}

	uint64_t base = ((uint64_t) area + size - 1) & ~(size - 1);
	munmap(area, base - (uint64_t) area);
	munmap((void *) (base + size), (uint64_t) area + size - base);

	if (is_oot_driver) {
		if (mprotect
		    ((void *) base, size, PROT_READ | PROT_WRITE | PROT_EXEC)) {
			perror("mprotect");
			munmap((void *) base, size);
			return 0;
		}
	}

	return base;
}

static bool encl_create(int dev_fd, unsigned long bin_size,
			struct sgx_secs *secs, uint64_t max_mmap_size)
{
	struct sgx_enclave_create ioc;
	int rc;
	uint64_t xfrm;
	uint64_t encl_size;

	memset(secs, 0, sizeof(*secs));
	secs->attributes = SGX_ATTR_MODE64BIT;
	if (enclave_debug)
		secs->attributes |= SGX_ATTR_DEBUG;

	get_sgx_xfrm_by_cpuid(&xfrm);
	secs->xfrm = xfrm;

	secs->miscselect = get_sgx_miscselect_by_cpuid();
	secs->ssa_frame_size =
		sgx_calc_ssaframesize(secs->miscselect, secs->xfrm);

	encl_size = bin_size + PAGE_SIZE * secs->ssa_frame_size;
	if (max_mmap_size) {
		if (max_mmap_size < encl_size) {
			fprintf(stderr,
				"Invalid enclave mmap size %lu, "
				"set enclave mmap size larger than %lu.\n",
				max_mmap_size, encl_size);
			return false;
		}
		encl_size = max_mmap_size;
	}

	for (secs->size = PAGE_SIZE; secs->size < encl_size;)
		secs->size <<= 1;

	uint64_t base = create_enclave_range(dev_fd, secs->size);
	if (!base)
		return false;

	secs->base = base;
	ioc.src = (unsigned long) secs;
	rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_CREATE, &ioc);
	if (rc) {
		fprintf(stderr, "ECREATE failed rc=%d, err=%d.\n", rc, errno);
		munmap((void *) secs->base, secs->size);
		return false;
	}

	return true;
}

static bool encl_add_pages_with_mrmask(int dev_fd, uint64_t addr, void *data,
				       unsigned long length, uint64_t flags)
{
	struct sgx_enclave_add_pages_with_mrmask ioc;
	struct sgx_secinfo secinfo;
	int rc;

	memset(&secinfo, 0, sizeof(secinfo));
	secinfo.flags = flags;

	ioc.src = (uint64_t) data;
	ioc.addr = addr;
	ioc.secinfo = (unsigned long) &secinfo;
	/* *INDENT-OFF* */
	ioc.mrmask = (__u16)-1;
	/* *INDENT-ON* */

	uint64_t added_size = 0;
	while (added_size < length) {
		rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_ADD_PAGES_WITH_MRMASK, &ioc);
		if (rc) {
			fprintf(stderr, "EADD failed rc=%d.\n", rc);
			return false;
		}

		ioc.addr += PAGE_SIZE;
		ioc.src += PAGE_SIZE;
		added_size += PAGE_SIZE;
	}

	return true;
}

static bool encl_add_pages(int dev_fd, uint64_t addr, void *data,
			   unsigned long length, uint64_t flags)
{
	struct sgx_enclave_add_pages ioc;
	struct sgx_secinfo secinfo;
	int rc;

	memset(&secinfo, 0, sizeof(secinfo));
	secinfo.flags = flags;

	ioc.src = (uint64_t) data;
	ioc.offset = addr;
	ioc.length = length;
	ioc.secinfo = (unsigned long) &secinfo;
	ioc.flags = SGX_PAGE_MEASURE;

	rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_ADD_PAGES, &ioc);
	if (rc) {
		fprintf(stderr, "EADD failed rc=%d.\n", rc);
		return false;
	}

	if (ioc.count != length) {
		fprintf(stderr, "EADD short of data.\n");
		return false;
	}

	return true;
}

static bool encl_build(struct sgx_secs *secs, void *bin, unsigned long bin_size,
		       struct sgx_sigstruct *sigstruct,
		       struct sgx_einittoken *token, uint64_t max_mmap_size)
{
	int dev_fd;
	int rc;
	uint64_t *add_memory = NULL;

	dev_fd = open(sgx_dev_path, O_RDWR);
	if (dev_fd < 0) {
		fprintf(stderr, "Unable to open %s\n", sgx_dev_path);
		return false;
	}

	if (!(sigstruct->body.attributes & SGX_ATTR_DEBUG))
		enclave_debug = false;

	if (!encl_create(dev_fd, bin_size, secs, max_mmap_size))
		goto out_dev_fd;

	uint64_t *ssa_frame = valloc(PAGE_SIZE * secs->ssa_frame_size);
	if (ssa_frame == NULL) {
		fprintf(stderr, "Failed malloc memory for ssa_frame\n");
		goto out_map;
	}
	memset(ssa_frame, 0, PAGE_SIZE * secs->ssa_frame_size);

	struct sgx_tcs *tcs = bin;
	tcs->ssa_offset = bin_size;

	uint64_t add_size = 0;
	if (max_mmap_size) {
		/* *INDENT-OFF* */
		add_size = max_mmap_size - PAGE_SIZE * secs->ssa_frame_size -
			   bin_size;
		/* *INDENT-ON* */
		if (max_mmap_size % PAGE_SIZE)
			add_size = (add_size / PAGE_SIZE + 1) * PAGE_SIZE;
		add_memory = valloc(add_size);
		if (add_memory == NULL) {
			fprintf(stderr,
				"Failed malloc memory for add_memory\n");
			goto out_add;
		}
		memset(add_memory, 0, add_size);
	}

	if (is_oot_driver) {
		if (!encl_add_pages_with_mrmask
		    (dev_fd, secs->base, bin, PAGE_SIZE, SGX_SECINFO_TCS))
			goto out_map;

		if (!encl_add_pages_with_mrmask
		    (dev_fd, secs->base + PAGE_SIZE, bin + PAGE_SIZE,
		     bin_size - PAGE_SIZE, SGX_REG_PAGE_FLAGS))
			goto out_map;

		if (!encl_add_pages_with_mrmask
		    (dev_fd, secs->base + bin_size, ssa_frame,
		     PAGE_SIZE * secs->ssa_frame_size, SGX_REG_PAGE_FLAGS))
			goto out_map;

		if (max_mmap_size) {
			if (!encl_add_pages_with_mrmask
			    (dev_fd,
			     secs->base + bin_size +
			     PAGE_SIZE * secs->ssa_frame_size, add_memory,
			     add_size, SGX_REG_PAGE_FLAGS))
				goto out_add;
		}
	} else {
		if (!encl_add_pages(dev_fd, 0, bin, PAGE_SIZE, SGX_SECINFO_TCS))
			goto out_map;

		if (!encl_add_pages(dev_fd, PAGE_SIZE, bin + PAGE_SIZE,
				    bin_size - PAGE_SIZE, SGX_REG_PAGE_FLAGS))
			goto out_map;

		if (!encl_add_pages(dev_fd, tcs->ssa_offset, ssa_frame,
				    PAGE_SIZE * secs->ssa_frame_size,
				    SGX_REG_PAGE_FLAGS))
			goto out_map;

		if (max_mmap_size) {
			if (!encl_add_pages
			    (dev_fd,
			     bin_size + PAGE_SIZE * secs->ssa_frame_size,
			     add_memory, add_size, SGX_REG_PAGE_FLAGS))
				goto out_add;
		}
	}

	if (is_oot_driver || no_sgx_flc) {
		struct sgx_enclave_init_with_token ioc;
		ioc.addr = secs->base;
		ioc.sigstruct = (uint64_t) sigstruct;
		ioc.einittoken = (uint64_t) token;
		rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_INIT_WITH_TOKEN, &ioc);
	} else {
		struct sgx_enclave_init ioc;
		ioc.sigstruct = (uint64_t) sigstruct;
		rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_INIT, &ioc);
	}

	if (rc) {
		printf("EINIT failed rc=%d\n", rc);
		goto out_map;
	}

	if (is_oot_driver)
		close(dev_fd);
	else {
		void *rc;

		rc = mmap((void *) secs->base, PAGE_SIZE,
			  PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED,
			  dev_fd, 0);
		if (rc == MAP_FAILED) {
			perror("mmap TCS");
			goto out_map;
		}

		rc = mmap((void *) secs->base + PAGE_SIZE,
			  add_size + bin_size +
			  PAGE_SIZE * (secs->ssa_frame_size - 1),
			  PROT_READ | PROT_WRITE | PROT_EXEC,
			  MAP_FIXED | MAP_SHARED, dev_fd, 0);
		if (rc == MAP_FAILED) {
			perror("mmap text & data");
			if (max_mmap_size)
				goto out_add;
			goto out_map;
		}

		enclave_fd = dev_fd;
	}

	free(ssa_frame);
	return true;
out_map:
	free(ssa_frame);
	munmap((void *) secs->base, secs->size);
out_add:
	free(ssa_frame);
	free(add_memory);
	munmap((void *) secs->base, secs->size);
out_dev_fd:
	close(dev_fd);
	return false;
}

/* *INDENT-OFF* */
static bool get_file_size(const char *path, off_t *bin_size)
{
	struct stat sb;
	int ret;

	ret = stat(path, &sb);
	if (ret) {
		perror("stat");
		return false;
	}

	if (!sb.st_size || sb.st_size & 0xfff) {
		fprintf(stderr, "Invalid blob size %lu\n", sb.st_size);
		return false;
	}

	*bin_size = sb.st_size;
	return true;
}

static bool encl_data_map(const char *path, void **bin, off_t *bin_size)
{
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "open() %s failed, errno=%d.\n", path, errno);
		return false;
	}

	if (!get_file_size(path, bin_size))
		goto err_out;

	*bin = mmap(NULL, *bin_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd,
		    0);
	if (*bin == MAP_FAILED) {
		fprintf(stderr, "mmap() %s failed, errno=%d.\n", path, errno);
		goto err_out;
	}

	close(fd);
	return true;

err_out:
	close(fd);
	return false;
}
/* *INDENT-ON* */

static bool load_sigstruct(const char *path, void *sigstruct)
{
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "open() %s failed, errno=%d.\n", path, errno);
		return false;
	}

	if (read(fd, sigstruct, sizeof(struct sgx_sigstruct)) !=
	    sizeof(struct sgx_sigstruct)) {
		fprintf(stderr, "read() %s failed, errno=%d.\n", path, errno);
		close(fd);
		return false;
	}

	close(fd);
	return true;
}

static void check_opts(const char *opt)
{
	if (!strcmp(opt, "no-sgx-flc"))
		no_sgx_flc = true;
	else if (!strcmp(opt, "debug"))
		debugging = true;
	else if (strstr(opt, "mmap-size")) {
		max_mmap_size = atoi(strchr(opt, '=') + 1);
	} else if (!strcmp(opt, "backend-kvm")) {
		backend_kvm = true;
	} else if (!strncmp(opt, "kvm-kernel=", 11)) {
		kvm_kernel = strdup(opt + 11);
	} else if (!strncmp(opt, "kvm-rootfs=", 11)) {
		kvm_rootfs = strdup(opt + 11);
	} else if (!strncmp(opt, "kvm-init=", 9)) {
		kvm_init = strdup(opt + 9);
	}
}

void parse_args(const char *args)
{
	char *a = strdup(args);
	if (!a)
		return;

	char *opt = strtok(a, " ");
	check_opts(opt);

	if (!opt) {
		free(a);
		return;
	}

	do {
		char *opt = strtok(NULL, " ");
		if (!opt)
			break;

		check_opts(opt);
	} while (1);

	free(a);
}

int encl_init()
{
	struct sgx_sigstruct sigstruct;
	struct sgx_einittoken token;
	off_t bin_size;
	void *bin;

	if (!encl_data_map(IMAGE, &bin, &bin_size))
		return -ENOENT;

	if (!load_sigstruct(SIGSTRUCT, &sigstruct))
		return -ENOENT;

	if (!is_launch_control_supported()) {
		if (!get_launch_token(&sigstruct, &token))
			return -ENOENT;
	}

	if (!encl_build
	    (&secs, bin, bin_size, &sigstruct, &token, max_mmap_size))
		return -EINVAL;

	return 0;
}

/* *INDENT-OFF* */
int __pal_init_v1(pal_attr_v1_t *attr)
{
	int ret;

	parse_args(attr->args);

	if (backend_kvm) {
		if (!kvm_kernel || !kvm_rootfs)
			return -EINVAL;

		kvm_vm = libvmm_create_vm();
		if (kvm_vm == NULL)
			return -EFAULT;

		/* TODO: config it, 256M, 1 vcpu, initrd, CID */
		libvmm_vm_set_memory(kvm_vm, 256);
		libvmm_vm_set_cpus(kvm_vm, 1);
		libvmm_vm_set_kernel(kvm_vm, kvm_kernel, NULL);
		libvmm_vm_set_rootfs(kvm_vm, kvm_rootfs);
		if (kvm_init)
			libvmm_vm_set_init(kvm_vm, kvm_init);
		libvmm_vm_set_vsock(kvm_vm, 3333);

		ret = libvmm_vm_init(kvm_vm);
		if (ret < 0)
			return ret;

		initialized = true;
		return 0;
	}

	tcs_busy = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (tcs_busy == MAP_FAILED)
		return -EINVAL;
	*(uint8_t *) tcs_busy = 0;

	ret = encl_init();
	if (ret != 0)
		return ret;

	char *result = malloc(sizeof(INIT_HELLO));
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

int __pal_exec(char *path, char *argv[], pal_stdio_fds *stdio, int *exit_code)
{
	if (path == NULL || argv == NULL || stdio == NULL || exit_code == NULL) {
		return -1;
	}

	FILE *fp = fdopen(stdio->stderr, "w");
	if (!fp)
		return -1;

	if (!initialized) {
		fprintf(fp, "enclave runtime skeleton uninitialized yet!\n");
		fclose(fp);
		return -1;
	}

	memcpy(&pal_stdio, stdio, sizeof(pal_stdio_fds));

	for (int i = 0; argv[i]; i++) {
		if (!strcmp(argv[i], "wait_timeout") && argv[i + 1]) {
			wait_timeout = atoi(argv[i + 1]);
			if (wait_timeout > 0)
				sleep(wait_timeout);
			break;
		}
	}

	fprintf(fp, "Enclave runtime skeleton initialization succeeded\n");
	fclose(fp);

	*exit_code = 0;

	return 0;
}

int __pal_create_process(pal_create_process_args *args)
{
	int pid;

	if (args == NULL || args->path == NULL || args->argv == NULL ||
	    args->pid == NULL || args->stdio == NULL) {
		return -1;
	}

	if (backend_kvm)
		return 0;

	/* SGX out-of-tree driver disallows the creation of shared enclave mapping
	 * between parent and child process, so simply launching __pal_exec() directly here.
	 */
	if (is_oot_driver) {
		return __pal_exec(args->path, args->argv, args->stdio,
				  &exit_code);
	}

	FILE *fp = fdopen(args->stdio->stderr, "w");
	if (!fp)
		return -1;

	if (!initialized) {
		fprintf(fp, "Enclave runtime skeleton uninitialized yet!\n");
		fclose(fp);
		return -1;
	}

	if ((pid = fork()) < 0) {
		fclose(fp);
		return -1;
	} else if (pid == 0) {
		int exit_code, ret;

		ret = __pal_exec(args->path, args->argv, args->stdio,
				 &exit_code);
		exit(ret ? ret : exit_code);
	} else
		*args->pid = pid;

	fclose(fp);
	return 0;
}

int wait4child(pal_exec_args *attr)
{
	int status;

	if (attr == NULL || attr->exit_value == NULL) {
		return -1;
	}

	if (!initialized) {
		fprintf(stderr,
			"Enclave runtime skeleton uninitialized yet!\n");
		return -1;
	}

	if (is_oot_driver) {
		*attr->exit_value = exit_code;
		return exit_code;
	}

	waitpid(attr->pid, &status, 0);

	if (WIFEXITED(status) || WIFSIGNALED(status))
		*attr->exit_value = WEXITSTATUS(status);

	return 0;
}
/* *INDENT-ON* */

int __pal_get_local_report(void *targetinfo, int targetinfo_len, void *report,
			   int *report_len)
{
	uint8_t report_data[64] = { 0, };
	struct sgx_report report_align;
	int ret;

	if (!initialized) {
		fprintf(stderr,
			"Enclave runtime skeleton uninitialized yet!\n");
		return -1;
	}

	if (backend_kvm)
		/* No implementation */
		return 0;

	if (targetinfo == NULL ||
	    targetinfo_len != sizeof(struct sgx_target_info)) {
		fprintf(stderr,
			"Input parameter targetinfo is NULL or targentinfo_len != sizeof(struct sgx_target_info)!\n");
		return -1;
	}

	if (report == NULL || report_len == NULL ||
	    *report_len < SGX_REPORT_SIZE) {
		fprintf(stderr,
			"Input parameter report is NULL or report_len is not enough!\n");
		return -1;
	}

	ret = SGX_ENTER_3_ARGS(ECALL_REPORT, (void *) secs.base, targetinfo,
			       report_data, &report_align);
	if (ret) {
		fprintf(stderr, "failed to get report\n");
		return ret;
	}

	memcpy(report, &report_align, SGX_REPORT_SIZE);
	if (debugging) {
		fprintf(stdout, "succeed to get local report\n");
	}

	return 0;
}

int __pal_kill(int pid, int sig)
{
	if (!initialized) {
		fprintf(stderr,
			"Enclave runtime skeleton uninitialized yet!\n");
		return -1;
	}

	if (backend_kvm)
		return 0;	/* TODO: libvmm_vm_kill(kvm_vm); */

	/* No implementation */
	return 0;
}

int __pal_destroy(void)
{
	FILE *fp = fdopen(pal_stdio.stderr, "w");
	if (!fp)
		return -1;

	if (!initialized) {
		fprintf(fp, "Enclave runtime skeleton uninitialized yet!\n");
		fclose(fp);
		return -1;
	}

	fclose(fp);

	if (backend_kvm)
		return libvmm_vm_exit(kvm_vm);

	close(enclave_fd);

	return 0;
}
