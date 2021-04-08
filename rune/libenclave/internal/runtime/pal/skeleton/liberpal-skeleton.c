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
#include <time.h>
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

#ifdef TLS_SERVER
bool tls_server = true;
#else
bool tls_server = false;
#endif

struct sgx_secs secs;
static pal_stdio_fds pal_stdio = { -1, -1, -1 };

bool initialized = false;
static int exit_code;
static char *sgx_dev_path;
static bool no_sgx_flc = false;
static int wait_timeout;
bool debugging = false;
bool is_oot_driver;
bool backend_kvm = false;
struct kvm *kvm_vm;
static const char *kvm_kernel;
static const char *kvm_rootfs;
static const char *kvm_init;
char *attester_type = "";
char *verifier_type = "";
char *tls_type = "";
char *crypto = "";
/*
 * For SGX in-tree driver, dev_fd cannot be closed until an enclave instance
 * intends to exit.
 */
int enclave_fd = -1;
void *tcs_busy;

__attribute__((constructor))
static void detect_driver_type(void)
{
	if (is_legacy_oot_kernel_driver()) {
		sgx_dev_path = "/dev/isgx";
		is_oot_driver = true;
		return;
	}

	is_oot_driver = false;

	if (is_dcap_oot_kernel_driver()) {
		sgx_dev_path = "/dev/sgx/enclave";
		return;
	}

	if (is_in_tree_kernel_driver()) {
		sgx_dev_path = "/dev/sgx_enclave";
		return;
	}

	fprintf(stderr, "no SGX device available\n");
	exit(1);
}

/*
 * In order to prevent from enclave null dereference attack,
 * the address space up to vm.mmap_min_addr should be included
 * in enclave range.
 */
static int create_enclave_range(int dev_fd, uint64_t mmap_size,
				struct enclave_info *encl_info,
				struct metadata *meta_data)
{
	uint64_t mmap_min_addr;

	if (get_mmap_min_addr(&mmap_min_addr) < 0)
		return -1;

	/* mmap_min_addr only affect the value of encl_offset when
	 * in tree driver with null_dereference_protection.
	 */
	if ((mmap_min_addr != meta_data->mmap_min_addr) && !is_oot_driver &&
	    meta_data->null_dereference_protection) {
		fprintf(stderr,
			"Invalid mmap_min_addr value, the valid mmap_min_addr is %ld\n",
			mmap_min_addr);
		return -1;
	}

	int flags = MAP_SHARED;
	int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	uint64_t encl_size;
	void *mmap_addr;

	/* If vm.mmap_min_addr is not configured as 0, OOT driver
	 * disallows to mmap(0), and thus there is no way to protect
	 * enclave against null dereference attack.
	 */
	if (meta_data->null_dereference_protection && is_oot_driver &&
	    mmap_min_addr) {
		fprintf(stderr,
			"Cannot protect enclave against null dereference attack "
			"when vm.mmap_min_addr is not configured of 0 in OOT driver.\n");
		return -1;
	}

	if (!meta_data->null_dereference_protection) {
		printf("WARNING: enclave is vulnerable to null dereference "
		       "attack. Careful consideration required prior to "
		       "setting -n option when signing. In additon, set "
		       "vm.mmap_min_addr=0 if using OOT driver.\n");

		encl_size = pow2(mmap_size);

		if (!is_oot_driver) {
			dev_fd = -1;
			prot = PROT_NONE;
			flags |= MAP_ANONYMOUS;
		}

		mmap_addr = mmap(NULL, encl_size * 2, prot, flags, dev_fd, 0);
		if (mmap_addr == MAP_FAILED) {
			perror("mmap");
			return -1;
		}

		/* Unmap unused areas */
		uint64_t mmap_base;
		/* *INDENT-OFF* */
		mmap_base = ((uint64_t) mmap_addr + encl_size - 1) &
			    ~(encl_size - 1);
		/* *INDENT-ON* */
		munmap(mmap_addr, mmap_base - (uint64_t) mmap_addr);

		/* VMA should be consistent with enclave range
		 * during EINIT. The tail padding to be unmapped must be
		 * located at mmap_base + encl_size.
		 */
		munmap((void *) (mmap_base + encl_size),
		       (uint64_t) mmap_addr + encl_size * 2 -
		       (mmap_base + encl_size));

		encl_info->mmap_base = mmap_base;
		encl_info->mmap_size = encl_size;
		encl_info->encl_base = mmap_base;
		encl_info->encl_size = encl_size;
		encl_info->encl_offset = 0;

		return 0;
	}

	uint64_t encl_offset = calc_enclave_offset(mmap_min_addr, true);
	if (is_oot_driver)
		printf("WARNING: enclave is not vulnerable to null "
		       "dereference attack. But setting "
		       "vm.mmap_min_addr=0 will violate the security "
		       "requirements of non-enclave application.\n");

	encl_size = pow2(encl_offset + mmap_size);
	flags |= MAP_FIXED;

	if (is_oot_driver) {
		/* OOT driver requires VMA is consistent with enclave range
		 * during EINIT.
		 */
		mmap_addr = (void *) 0;
		mmap_size = encl_size;
	} else {
		mmap_addr = (void *) encl_offset;
		prot = PROT_NONE;
		flags |= MAP_ANONYMOUS;
		dev_fd = -1;
	}

	if (mmap(mmap_addr, mmap_size, prot, flags, dev_fd, 0) == MAP_FAILED) {
		perror("mmap()");
		return -1;
	}

	encl_info->mmap_base = (uint64_t) mmap_addr;
	encl_info->mmap_size = mmap_size;
	encl_info->encl_base = 0;
	encl_info->encl_size = encl_size;
	encl_info->encl_offset = encl_offset;

	return 0;
}

/* Sanity check attributes to prevent possible tampering */
static bool check_sgx_attributes(const uint64_t req_attrs,
				 const uint64_t req_attrs_mask)
{
	/* skeleton doesn't support 32-bit mode */
	uint64_t enforced_pattern = SGX_ATTR_MODE64BIT;

	if (req_attrs & ~SGX_ATTR_ALLOWED_MASK) {
		fprintf(stderr,
			"Invalid attributes value. The unsupported attributes %#lx are set.\n",
			req_attrs & ~SGX_ATTR_ALLOWED_MASK);
		return false;
	}

	if ((req_attrs & enforced_pattern) != enforced_pattern) {
		fprintf(stderr,
			"Invalid attributes value. The bits %#lx must be set.\n",
			enforced_pattern & ~req_attrs);
		return false;
	}

	if ((req_attrs_mask & enforced_pattern) != enforced_pattern) {
		fprintf(stderr,
			"Invalid attributes mask value. The bits %#lx must be set.\n",
			enforced_pattern & ~req_attrs_mask);
		return false;
	}

	return true;
}

static bool check_sgx_xfrm(uint64_t probed_xfrm, uint64_t req_xfrm,
			   uint64_t req_xfrm_mask)
{
	uint64_t enforced_pattern = SGX_XFRM_LEGACY;

	if ((req_xfrm & enforced_pattern) != enforced_pattern) {
		fprintf(stderr,
			"Invalid xfrm value. The bits %#lx must be set.\n",
			enforced_pattern & ~req_xfrm);
		return false;
	}

	if ((req_xfrm_mask & enforced_pattern) != enforced_pattern) {
		fprintf(stderr,
			"Invalid xfrm mask value. The bits %#lx must be set.\n",
			enforced_pattern & ~req_xfrm_mask);
		return false;
	}

	/* Check whether the requesting xfrm is supported */
	if ((req_xfrm & req_xfrm_mask) & ~probed_xfrm) {
		fprintf(stderr, "Unsupported xfrm bits %#lx.\n",
			(req_xfrm & req_xfrm_mask) & ~probed_xfrm);
		return false;
	}

	return true;
}

static bool encl_create(int dev_fd, unsigned long bin_size,
			struct sgx_secs *secs, struct enclave_info *encl_info,
			struct metadata *meta_data,
			struct sgx_sigstruct *sigstruct)
{
	if (debugging)
		fprintf(stdout, "sig.attrs %#lx, sig.attrs_mask %#lx\n",
			sigstruct->body.attributes,
			sigstruct->body.attributes_mask);

	// *INDENT-OFF*
	if (!check_sgx_attributes(sigstruct->body.attributes,
				  sigstruct->body.attributes_mask))
		return false;
	// *INDENT-ON*
	secs->attributes = sigstruct->body.attributes;
	if (debugging)
		secs->attributes |= SGX_ATTR_DEBUG;

	uint64_t probed_xfrm;
	get_sgx_xfrm_by_cpuid(&probed_xfrm);

	if (debugging)
		fprintf(stdout,
			"probed xfrm %#lx, sig.xfrm %#lx, sig.xfrm_mask %#lx\n",
			probed_xfrm, sigstruct->body.xfrm,
			sigstruct->body.xfrm_mask);

	// *INDENT-OFF*
	if (!check_sgx_xfrm(probed_xfrm, sigstruct->body.xfrm,
			    sigstruct->body.xfrm_mask))
		return false;
	// *INDENT-ON*
	secs->xfrm = sigstruct->body.xfrm;

	secs->miscselect = get_sgx_miscselect_by_cpuid();
	secs->ssa_frame_size =
		sgx_calc_ssaframesize(secs->miscselect, secs->xfrm);

	uint64_t mmap_size = bin_size + PAGE_SIZE * secs->ssa_frame_size;
	if (meta_data->max_mmap_size) {
		if (meta_data->max_mmap_size < mmap_size) {
			fprintf(stderr,
				"Invalid enclave mmap size %lu, "
				"set enclave mmap size larger than %lu.\n",
				meta_data->max_mmap_size, mmap_size);
			return false;
		}
		mmap_size = meta_data->max_mmap_size;
	}

	if (mmap_size % PAGE_SIZE)
		mmap_size = (mmap_size / PAGE_SIZE + 1) * PAGE_SIZE;

	if (create_enclave_range(dev_fd, mmap_size, encl_info, meta_data) < 0)
		return false;

	printf("enclave range [%#016lx, %#016lx], length %ld-byte\n",
	       encl_info->encl_base,
	       encl_info->encl_base + encl_info->encl_size - 1,
	       encl_info->encl_size);
	printf("enclave mmap [%#016lx, %#016lx], length %ld-byte\n",
	       encl_info->mmap_base,
	       encl_info->mmap_base + encl_info->mmap_size - 1,
	       encl_info->mmap_size);
	printf("load area [%#016lx, %#016lx], length %ld-byte\n",
	       encl_info->encl_base + encl_info->encl_offset,
	       encl_info->encl_base + encl_info->encl_offset +
	       encl_info->mmap_size - 1, encl_info->mmap_size);

	secs->base = encl_info->encl_base;
	secs->size = encl_info->encl_size;

	struct sgx_enclave_create ioc;
	ioc.src = (unsigned long) secs;
	int rc = ioctl(dev_fd, SGX_IOC_ENCLAVE_CREATE, &ioc);
	if (rc) {
		fprintf(stderr, "ECREATE failed rc=%d, err=%d.\n", rc, errno);
		munmap((void *) encl_info->mmap_base, encl_info->mmap_size);
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
		       struct sgx_einittoken *token,
		       struct enclave_info *encl_info)
{
	int dev_fd;
	int rc;
	uint64_t *add_memory = NULL;
	struct metadata meta_data;

	/* Get metadata from enclave image. */
	memset(&meta_data, 0, sizeof(struct metadata));
	meta_data = *(struct metadata *) (bin + bin_size - PAGE_SIZE);

	dev_fd = open(sgx_dev_path, O_RDWR);
	if (dev_fd < 0) {
		fprintf(stderr, "Unable to open %s\n", sgx_dev_path);
		return false;
	}

	memset(secs, 0, sizeof(*secs));

	/* Work around buggy indent */
	{
		// *INDENT-OFF*
		if (!encl_create(dev_fd, bin_size, secs, encl_info, &meta_data,
				 sigstruct))
			goto out_dev_fd;
		// *INDENT-ON*
	}

	uint64_t *ssa_frame = valloc(PAGE_SIZE * secs->ssa_frame_size);
	if (ssa_frame == NULL) {
		fprintf(stderr, "Failed malloc memory for ssa_frame\n");
		goto out_encl_create;
	}
	memset(ssa_frame, 0, PAGE_SIZE * secs->ssa_frame_size);

	struct sgx_tcs *tcs = bin;
	tcs->ssa_offset = encl_info->encl_offset + bin_size;
	tcs->entry_offset += encl_info->encl_offset;

	uint64_t add_size = 0;
	if (meta_data.max_mmap_size) {
		/* *INDENT-OFF* */
		add_size = meta_data.max_mmap_size -
			PAGE_SIZE * secs->ssa_frame_size - bin_size;
		/* *INDENT-ON* */
		if (meta_data.max_mmap_size % PAGE_SIZE)
			add_size = (add_size / PAGE_SIZE + 1) * PAGE_SIZE;
		add_memory = valloc(add_size);
		if (add_memory == NULL) {
			fprintf(stderr,
				"Failed malloc memory for add_memory\n");
			goto out_encl_create;
		}
		memset(add_memory, 0, add_size);
	}

	uint64_t load_base;

	if (is_oot_driver) {
		load_base = encl_info->encl_base + encl_info->encl_offset;

		/* *INDENT-OFF* */
		if (!encl_add_pages_with_mrmask(dev_fd, load_base, bin,
						PAGE_SIZE, SGX_SECINFO_TCS))
			goto out_add_memory;

		if (!encl_add_pages_with_mrmask(dev_fd, load_base + PAGE_SIZE,
						bin + PAGE_SIZE,
						bin_size - PAGE_SIZE,
						SGX_REG_PAGE_FLAGS))
			goto out_add_memory;

		if (!encl_add_pages_with_mrmask(dev_fd, load_base + bin_size,
						ssa_frame,
						PAGE_SIZE * secs->ssa_frame_size,
						SGX_REG_PAGE_FLAGS))
			goto out_add_memory;

		if (meta_data.max_mmap_size) {
			if (!encl_add_pages_with_mrmask(dev_fd,
							load_base + bin_size +
							PAGE_SIZE * secs->ssa_frame_size,
							add_memory,
							add_size,
							SGX_REG_PAGE_FLAGS))
				goto out_add_memory;
		}
		/* *INDENT-ON* */
	} else {
		load_base = encl_info->encl_offset;

		/* *INDENT-OFF* */
		if (!encl_add_pages(dev_fd, load_base, bin, PAGE_SIZE,
				    SGX_SECINFO_TCS))
			goto out_add_memory;

		if (!encl_add_pages(dev_fd, load_base + PAGE_SIZE,
				    bin + PAGE_SIZE, bin_size - PAGE_SIZE,
				    SGX_REG_PAGE_FLAGS))
			goto out_add_memory;

		if (!encl_add_pages(dev_fd, load_base + bin_size,
				    ssa_frame, PAGE_SIZE * secs->ssa_frame_size,
				    SGX_REG_PAGE_FLAGS))
			goto out_add_memory;

		if (meta_data.max_mmap_size) {
			if (!encl_add_pages(dev_fd,
					    load_base + bin_size +
					    PAGE_SIZE * secs->ssa_frame_size,
					    add_memory, add_size,
					    SGX_REG_PAGE_FLAGS))
				goto out_add_memory;
		}
		/* *INDENT-ON* */
	}

	if (is_oot_driver || no_sgx_flc) {
		struct sgx_enclave_init_with_token ioc;
		ioc.addr = encl_info->mmap_base;
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
		goto out_add_memory;
	}

	if (is_oot_driver) {
		close(dev_fd);
		free(ssa_frame);

		return true;
	}

	/* In-tree driver stuffs */

	if (mmap((void *) encl_info->mmap_base, PAGE_SIZE,
		 PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED,
		 dev_fd, 0) == MAP_FAILED) {
		perror("mmap TCS");
		goto out_add_memory;
	}

	if (mmap((void *) encl_info->mmap_base + PAGE_SIZE,
		 add_size + bin_size +
		 PAGE_SIZE * (secs->ssa_frame_size - 1),
		 PROT_READ | PROT_WRITE | PROT_EXEC,
		 MAP_FIXED | MAP_SHARED, dev_fd, 0) == MAP_FAILED) {
		perror("mmap text & data");
		goto out_add_memory;
	}

	enclave_fd = dev_fd;
	free(ssa_frame);

	return true;

out_add_memory:
	free(add_memory);
out_encl_create:
	munmap((void *) encl_info->mmap_base, encl_info->mmap_size);
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

	if (!sb.st_size) {
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
	else if (!strcmp(opt, "backend-kvm"))
		backend_kvm = true;
	else if (!strncmp(opt, "kvm-kernel=", 11))
		kvm_kernel = strdup(opt + 11);
	else if (!strncmp(opt, "kvm-rootfs=", 11))
		kvm_rootfs = strdup(opt + 11);
	else if (!strncmp(opt, "kvm-init=", 9))
		kvm_init = strdup(opt + 9);
	else if (!strncmp(opt, "attester=", 9))
		attester_type = strdup(opt + 9);
	else if (!strncmp(opt, "verifier=", 9))
		verifier_type = strdup(opt + 9);
	else if (!strncmp(opt, "tls=", 4))
		tls_type = strdup(opt + 4);
	else if (!strncmp(opt, "crypto=", 7))
		crypto = strdup(opt + 7);
}

void parse_args(const char *args)
{
	if (!args || args[0] == '\0')
		return;

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

int encl_init(struct enclave_info *encl_info)
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

	bin_size = align_up(bin_size, PAGE_SIZE);
	if (!encl_build(&secs, bin, bin_size, &sigstruct, &token, encl_info))
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

	struct enclave_info encl_info;
	ret = encl_init(&encl_info);
	if (ret != 0)
		return ret;

	char *result = malloc(sizeof(INIT_HELLO));
	if (!result) {
		fprintf(stderr, "fail to malloc INIT_HELLO\n");
		return -ENOMEM;
	}

	ret = SGX_ENTER_1_ARG(ECALL_INIT,
			      (void *) encl_info.encl_base +
			      encl_info.encl_offset, result);
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
			if (wait_timeout > 0) {
				struct timespec req, rem;
				req.tv_sec = wait_timeout;
				nanosleep(&req, &rem);
				while (rem.tv_sec > 0 || rem.tv_nsec > 0) {
					req = rem;
					nanosleep(&req, &rem);
				}
			}
			break;
		}
	}

	fprintf(fp, "Enclave runtime skeleton initialization succeeded\n");
	fflush(fp);

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

	if (backend_kvm || tls_server)
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

int __pal_get_local_report(void *targetinfo, int targetinfo_len,
			   void *report, int *report_len)
{
	uint8_t report_data[64] = { 0, };
	struct sgx_report report_align;
	int ret;

	FILE *fp_stderr = stderr;
	FILE *fp_stdout = stdout;

	if (pal_stdio.stderr != -1) {
		fp_stderr = fdopen(pal_stdio.stderr, "w");
		if (!fp_stderr)
			return -1;
	}

	if (pal_stdio.stdout != -1) {
		fp_stdout = fdopen(pal_stdio.stdout, "w");
		if (!fp_stdout)
			return -1;
	}

	if (!initialized) {
		fprintf(fp_stderr,
			"Enclave runtime skeleton uninitialized yet!\n");
		fflush(fp_stderr);
		return -1;
	}

	if (backend_kvm || tls_server)
		/* No implementation */
		return 0;

	if (targetinfo == NULL ||
	    targetinfo_len != sizeof(struct sgx_target_info)) {
		fprintf(fp_stderr,
			"Input parameter targetinfo is NULL or targentinfo_len != sizeof(struct sgx_target_info)!\n");
		fflush(fp_stderr);
		return -1;
	}

	if (report == NULL || report_len == NULL ||
	    *report_len < SGX_REPORT_SIZE) {
		fprintf(fp_stderr,
			"Input parameter report is NULL or report_len is not enough!\n");
		fflush(fp_stderr);
		return -1;
	}

	ret = SGX_ENTER_3_ARGS(ECALL_REPORT, (void *) secs.base, targetinfo,
			       report_data, &report_align);
	if (ret) {
		fprintf(fp_stderr, "failed to get report\n");
		fflush(fp_stderr);
		return ret;
	}

	memcpy(report, &report_align, SGX_REPORT_SIZE);
	if (debugging) {
		fprintf(fp_stdout, "succeed to get local report\n");
	}

	return 0;
}

int __pal_kill(int pid, int sig)
{
	FILE *fp = stderr;

	if (pal_stdio.stderr != -1) {
		fp = fdopen(pal_stdio.stderr, "w");
		if (!fp)
			return -1;
	}

	if (!initialized) {
		fprintf(fp, "Enclave runtime skeleton uninitialized yet!\n");
		fflush(fp);
		return -1;
	}

	if (backend_kvm || tls_server)
		return 0;	/* TODO: libvmm_vm_kill(kvm_vm); */

	/* No implementation */
	return 0;
}

int __pal_destroy(void)
{
	FILE *fp = stderr;

	if (pal_stdio.stderr != -1) {
		fp = fdopen(pal_stdio.stderr, "w");
		if (!fp)
			return -1;
	}

	if (!initialized) {
		fprintf(fp, "Enclave runtime skeleton uninitialized yet!\n");
		fflush(fp);
		return -1;
	}

	if (backend_kvm)
		return libvmm_vm_exit(kvm_vm);

	if (tls_server)
		return 0;

	close(enclave_fd);

	return 0;
}
