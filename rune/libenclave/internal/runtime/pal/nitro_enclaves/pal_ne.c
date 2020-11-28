#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/mman.h>
#include <linux/nitro_enclaves.h>
#include <linux/vm_sockets.h>

#include "pal_ne.h"

/**
 * NE_DEV_NAME - Nitro Enclaves (NE) misc device that provides the ioctl interface.
 */
#define NE_DEV_NAME			"/dev/nitro_enclaves"

/**
 * NE_POLL_WAIT_TIME - Timeout in seconds for each poll event.
 */
#define NE_POLL_WAIT_TIME		(60)
/**
 * NE_POLL_WAIT_TIME_MS - Timeout in milliseconds for each poll event.
 */
#define NE_POLL_WAIT_TIME_MS		(NE_POLL_WAIT_TIME * 1000)

/**
 * NE_SLEEP_TIME - Amount of time in seconds for the process to keep the enclave alive.
 */
#define NE_SLEEP_TIME			(300)

/**
 * NE_DEFAULT_NR_VCPUS - Default number of vCPUs set for an enclave.
 */
#define NE_DEFAULT_NR_VCPUS		(2)

/**
 * NE_MIN_MEM_REGION_SIZE - Minimum size of a memory region - 2 MiB.
 */
#define NE_MIN_MEM_REGION_SIZE		(2 * 1024 * 1024)

/**
 * NE_DEFAULT_NR_MEM_REGIONS - Default number of memory regions of 2 MiB set for
 *			       an enclave.
 */
#define NE_DEFAULT_NR_MEM_REGIONS	(256)

/**
 * NE_IMAGE_LOAD_HEARTBEAT_CID - Vsock CID for enclave image loading heartbeat logic.
 */
#define NE_IMAGE_LOAD_HEARTBEAT_CID	(3)
/**
 * NE_IMAGE_LOAD_HEARTBEAT_PORT - Vsock port for enclave image loading heartbeat logic.
 */
#define NE_IMAGE_LOAD_HEARTBEAT_PORT	(9000)
/**
 * NE_IMAGE_LOAD_HEARTBEAT_VALUE - Heartbeat value for enclave image loading.
 */
#define NE_IMAGE_LOAD_HEARTBEAT_VALUE	(0xb7)

/**
 * struct ne_user_mem_region - User space memory region set for an enclave.
 * @userspace_addr:	Address of the user space memory region.
 * @memory_size:	Size of the user space memory region.
 */
struct ne_user_mem_region {
	void *userspace_addr;
	size_t memory_size;
};

/**
 * Global Variable
 */
char *eif_image = NULL;
int enclave_fd = -1;
unsigned int ne_vcpu_nums = NE_DEFAULT_NR_VCPUS;
unsigned int ne_mem_regions = NE_DEFAULT_NR_MEM_REGIONS;
struct ne_user_mem_region ne_user_mem_regions[NE_DEFAULT_NR_MEM_REGIONS] = { };

/**
 * ne_create_vm() - Create a slot for the enclave VM.
 * @ne_dev_fd:		The file descriptor of the NE misc device.
 * @slot_uid:		The generated slot uid for the enclave.
 * @enclave_fd :	The generated file descriptor for the enclave.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_create_vm(int ne_dev_fd, unsigned long *slot_uid, int *enclave_fd)
{
	int rc = -EINVAL;
	*enclave_fd = ioctl(ne_dev_fd, NE_CREATE_VM, slot_uid);

	if (*enclave_fd < 0) {
		rc = *enclave_fd;
		switch (errno) {
		case NE_ERR_NO_CPUS_AVAIL_IN_POOL:{
				printf("Error in create VM, no CPUs available in the NE CPU pool\n");

				break;
			}

		default:
			printf("Error in create VM [%m]\n");
		}

		return rc;
	}

	return 0;
}

/**
 * ne_poll_enclave_fd() - Thread function for polling the enclave fd.
 * @data:	Argument provided for the polling function.
 *
 * Context: Process context.
 * Return:
 * * NULL on success / failure.
 */
void *ne_poll_enclave_fd(void *data)
{
	int enclave_fd = *(int *) data;
	struct pollfd fds[1] = { };
	int i = 0;
	int rc = -EINVAL;

	printf("Running from poll thread, enclave fd %d\n", enclave_fd);

	fds[0].fd = enclave_fd;
	fds[0].events = POLLIN | POLLERR | POLLHUP;

	/* Keep on polling until the current process is terminated. */
	while (1) {
		printf("[iter %d] Polling ...\n", i);

		rc = poll(fds, 1, NE_POLL_WAIT_TIME_MS);
		if (rc < 0) {
			printf("Error in poll [%m]\n");

			return NULL;
		}

		i++;

		if (!rc) {
			printf("Poll: %d seconds elapsed\n",
			       i * NE_POLL_WAIT_TIME);

			continue;
		}

		printf("Poll received value 0x%x\n", fds[0].revents);

		if (fds[0].revents & POLLHUP) {
			printf("Received POLLHUP\n");

			return NULL;
		}

		if (fds[0].revents & POLLNVAL) {
			printf("Received POLLNVAL\n");

			return NULL;
		}
	}

	return NULL;
}

/**
 * ne_alloc_user_mem_region() - Allocate a user space memory region for an enclave.
 * @ne_user_mem_region:	User space memory region allocated using hugetlbfs.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_alloc_user_mem_region(struct ne_user_mem_region
				    *ne_user_mem_region)
{
	/**
	 * Check available hugetlb encodings for different huge page sizes in
	 * include/uapi/linux/mman.h.
	 */
	ne_user_mem_region->userspace_addr =
		mmap(NULL, ne_user_mem_region->memory_size,
		     PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB,
		     -1, 0);
	if (ne_user_mem_region->userspace_addr == MAP_FAILED) {
		printf("Error in mmap memory [%m]\n");

		return -1;
	}

	return 0;
}

/**
 * ne_load_enclave_image() - Place the enclave image in the enclave memory.
 * @enclave_fd :		The file descriptor associated with the enclave.
 * @ne_user_mem_regions:	User space memory regions allocated for the enclave.
 * @enclave_image_path :	The file path of the enclave image.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_load_enclave_image(int enclave_fd,
				 struct ne_user_mem_region
				 ne_user_mem_regions[],
				 char *enclave_image_path)
{
	unsigned char *enclave_image = NULL;
	int enclave_image_fd = -1;
	size_t enclave_image_size = 0;
	size_t enclave_memory_size = 0;
	unsigned long i = 0;
	size_t image_written_bytes = 0;
	struct ne_image_load_info image_load_info = {
		.flags = NE_EIF_IMAGE,
	};
	struct stat image_stat_buf = { };
	int rc = -EINVAL;
	size_t temp_image_offset = 0;

	for (i = 0; i < NE_DEFAULT_NR_MEM_REGIONS; i++)
		enclave_memory_size += ne_user_mem_regions[i].memory_size;

	rc = stat(enclave_image_path, &image_stat_buf);
	if (rc < 0) {
		printf("Error in get image stat info [%m]\n");

		return rc;
	}

	enclave_image_size = image_stat_buf.st_size;

	if (enclave_memory_size < enclave_image_size) {
		printf("The enclave memory is smaller than the enclave image size\n");

		return -ENOMEM;
	}

	rc = ioctl(enclave_fd, NE_GET_IMAGE_LOAD_INFO, &image_load_info);
	if (rc < 0) {
		switch (errno) {
		case NE_ERR_NOT_IN_INIT_STATE:{
				printf("Error in get image load info, enclave not in init state\n");

				break;
			}

		case NE_ERR_INVALID_FLAG_VALUE:{
				printf("Error in get image load info, provided invalid flag\n");

				break;
			}

		default:
			printf("Error in get image load info [%m]\n");
		}

		return rc;
	}

	printf("Enclave image offset in enclave memory is %lld\n",
	       image_load_info.memory_offset);

	enclave_image_fd = open(enclave_image_path, O_RDONLY);
	if (enclave_image_fd < 0) {
		printf("Error in open enclave image file [%m]\n");

		return enclave_image_fd;
	}

	enclave_image = mmap(NULL, enclave_image_size, PROT_READ,
			     MAP_PRIVATE, enclave_image_fd, 0);
	if (enclave_image == MAP_FAILED) {
		printf("Error in mmap enclave image [%m]\n");

		return -1;
	}

	temp_image_offset = image_load_info.memory_offset;

	for (i = 0; i < NE_DEFAULT_NR_MEM_REGIONS; i++) {
		size_t bytes_to_write = 0;
		size_t memory_offset = 0;
		size_t memory_size = ne_user_mem_regions[i].memory_size;
		size_t remaining_bytes = 0;
		void *userspace_addr = ne_user_mem_regions[i].userspace_addr;

		if (temp_image_offset >= memory_size) {
			temp_image_offset -= memory_size;

			continue;
		} else if (temp_image_offset != 0) {
			memory_offset = temp_image_offset;
			memory_size -= temp_image_offset;
			temp_image_offset = 0;
		}

		remaining_bytes = enclave_image_size - image_written_bytes;
		bytes_to_write = memory_size < remaining_bytes ?
			memory_size : remaining_bytes;

		memcpy(userspace_addr + memory_offset,
		       enclave_image + image_written_bytes, bytes_to_write);

		image_written_bytes += bytes_to_write;

		if (image_written_bytes == enclave_image_size)
			break;
	}

	munmap(enclave_image, enclave_image_size);

	close(enclave_image_fd);

	return 0;
}

/**
 * ne_set_user_mem_region() - Set a user space memory region for the given enclave.
 * @enclave_fd :		The file descriptor associated with the enclave.
 * @ne_user_mem_region :	User space memory region to be set for the enclave.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_set_user_mem_region(int enclave_fd,
				  struct ne_user_mem_region ne_user_mem_region)
{
	struct ne_user_memory_region mem_region = {
		.flags = NE_DEFAULT_MEMORY_REGION,
		.memory_size = ne_user_mem_region.memory_size,
		.userspace_addr = (__u64) ne_user_mem_region.userspace_addr,
	};
	int rc = -EINVAL;

	rc = ioctl(enclave_fd, NE_SET_USER_MEMORY_REGION, &mem_region);
	if (rc < 0) {
		switch (errno) {
		case NE_ERR_NOT_IN_INIT_STATE:{
				printf("Error in set user memory region, enclave not in init state\n");

				break;
			}

		case NE_ERR_INVALID_MEM_REGION_SIZE:{
				printf("Error in set user memory region, mem size not multiple of 2 MiB\n");

				break;
			}

		case NE_ERR_INVALID_MEM_REGION_ADDR:{
				printf("Error in set user memory region, invalid user space address\n");

				break;
			}

		case NE_ERR_UNALIGNED_MEM_REGION_ADDR:{
				printf("Error in set user memory region, unaligned user space address\n");

				break;
			}

		case NE_ERR_MEM_REGION_ALREADY_USED:{
				printf("Error in set user memory region, memory region already used\n");

				break;
			}

		case NE_ERR_MEM_NOT_HUGE_PAGE:{
				printf("Error in set user memory region, not backed by huge pages\n");

				break;
			}

		case NE_ERR_MEM_DIFFERENT_NUMA_NODE:{
				printf("Error in set user memory region, different NUMA node than CPUs\n");

				break;
			}

		case NE_ERR_MEM_MAX_REGIONS:{
				printf("Error in set user memory region, max memory regions reached\n");

				break;
			}

		case NE_ERR_INVALID_PAGE_SIZE:{
				printf("Error in set user memory region, has page not multiple of 2 MiB\n");

				break;
			}

		case NE_ERR_INVALID_FLAG_VALUE:{
				printf("Error in set user memory region, provided invalid flag\n");

				break;
			}

		default:
			printf("Error in set user memory region [%m]\n");
		}

		return rc;
	}

	return 0;
}

/**
 * ne_free_mem_regions() - Unmap all the user space memory regions that were set
 *			   aside for the enclave.
 * @ne_user_mem_regions:	The user space memory regions associated with an enclave.
 *
 * Context: Process context.
 */
static void ne_free_mem_regions(struct ne_user_mem_region ne_user_mem_regions[])
{
	unsigned int i = 0;

	for (i = 0; i < NE_DEFAULT_NR_MEM_REGIONS; i++)
		munmap(ne_user_mem_regions[i].userspace_addr,
		       ne_user_mem_regions[i].memory_size);
}

/**
 * ne_add_vcpu() - Add a vCPU to the given enclave.
 * @enclave_fd :	The file descriptor associated with the enclave.
 * @vcpu_id:		vCPU id to be set for the enclave, either provided or
 *			auto-generated (if provided vCPU id is 0).
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_add_vcpu(int enclave_fd, unsigned int *vcpu_id)
{
	int rc = -EINVAL;

	rc = ioctl(enclave_fd, NE_ADD_VCPU, vcpu_id);
	if (rc < 0) {
		switch (errno) {
		case NE_ERR_NO_CPUS_AVAIL_IN_POOL:{
				printf("Error in add vcpu, no CPUs available in the NE CPU pool\n");

				break;
			}

		case NE_ERR_VCPU_ALREADY_USED:{
				printf("Error in add vcpu, the provided vCPU is already used\n");

				break;
			}

		case NE_ERR_VCPU_NOT_IN_CPU_POOL:{
				printf("Error in add vcpu, the provided vCPU is not in the NE CPU pool\n");

				break;
			}

		case NE_ERR_VCPU_INVALID_CPU_CORE:{
				printf("Error in add vcpu, the core id of the provided vCPU is invalid\n");

				break;
			}

		case NE_ERR_NOT_IN_INIT_STATE:{
				printf("Error in add vcpu, enclave not in init state\n");

				break;
			}

		case NE_ERR_INVALID_VCPU:{
				printf("Error in add vcpu, the provided vCPU is out of avail CPUs range\n");

				break;
			}

		default:
			printf("Error in add vcpu [%m]\n");

		}
		return rc;
	}

	return 0;
}

/**
 * ne_start_enclave() - Start the given enclave.
 * @enclave_fd :		The file descriptor associated with the enclave.
 * @enclave_start_info :	Enclave metadata used for starting e.g. vsock CID.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_start_enclave(int enclave_fd,
			    struct ne_enclave_start_info *enclave_start_info)
{
	int rc = -EINVAL;

	rc = ioctl(enclave_fd, NE_START_ENCLAVE, enclave_start_info);
	if (rc < 0) {
		switch (errno) {
		case NE_ERR_NOT_IN_INIT_STATE:{
				printf("Error in start enclave, enclave not in init state\n");

				break;
			}

		case NE_ERR_NO_MEM_REGIONS_ADDED:{
				printf("Error in start enclave, no memory regions have been added\n");

				break;
			}

		case NE_ERR_NO_VCPUS_ADDED:{
				printf("Error in start enclave, no vCPUs have been added\n");

				break;
			}

		case NE_ERR_FULL_CORES_NOT_USED:{
				printf("Error in start enclave, enclave has no full cores set\n");

				break;
			}

		case NE_ERR_ENCLAVE_MEM_MIN_SIZE:{
				printf("Error in start enclave, enclave memory is less than min size\n");

				break;
			}

		case NE_ERR_INVALID_FLAG_VALUE:{
				printf("Error in start enclave, provided invalid flag\n");

				break;
			}

		case NE_ERR_INVALID_ENCLAVE_CID:{
				printf("Error in start enclave, provided invalid enclave CID\n");

				break;
			}

		default:
			printf("Error in start enclave [%m]\n");
		}

		return rc;
	}

	return 0;
}

/**
 * ne_start_enclave_check_booted() - Start the enclave and wait for a hearbeat
 *				     from it, on a newly created vsock channel,
 *				     to check it has booted.
 * @enclave_fd :	The file descriptor associated with the enclave.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
static int ne_start_enclave_check_booted(int enclave_fd)
{
	struct sockaddr_vm client_vsock_addr = { };
	int client_vsock_fd = -1;
	socklen_t client_vsock_len = sizeof(client_vsock_addr);
	struct ne_enclave_start_info enclave_start_info = { };
	struct pollfd fds[1] = { };
	int rc = -EINVAL;
	unsigned char recv_buf = 0;
	struct sockaddr_vm server_vsock_addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = NE_IMAGE_LOAD_HEARTBEAT_CID,
		.svm_port = NE_IMAGE_LOAD_HEARTBEAT_PORT,
	};
	int server_vsock_fd = -1;

	server_vsock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (server_vsock_fd < 0) {
		rc = server_vsock_fd;

		printf("Error in socket [%m]\n");

		return rc;
	}

	rc = bind(server_vsock_fd, (struct sockaddr *) &server_vsock_addr,
		  sizeof(server_vsock_addr));
	if (rc < 0) {
		printf("Error in bind [%m]\n");

		goto out;
	}

	rc = listen(server_vsock_fd, 1);
	if (rc < 0) {
		printf("Error in listen [%m]\n");

		goto out;
	}

	rc = ne_start_enclave(enclave_fd, &enclave_start_info);
	if (rc < 0)
		goto out;

	printf("Enclave started, CID %llu\n", enclave_start_info.enclave_cid);

	fds[0].fd = server_vsock_fd;
	fds[0].events = POLLIN;

	rc = poll(fds, 1, NE_POLL_WAIT_TIME_MS);
	if (rc < 0) {
		printf("Error in poll [%m]\n");

		goto out;
	}

	if (!rc) {
		printf("Poll timeout, %d seconds elapsed\n", NE_POLL_WAIT_TIME);

		rc = -ETIMEDOUT;

		goto out;
	}

	if ((fds[0].revents & POLLIN) == 0) {
		printf("Poll received value %d\n", fds[0].revents);

		rc = -EINVAL;

		goto out;
	}

	rc = accept(server_vsock_fd, (struct sockaddr *) &client_vsock_addr,
		    &client_vsock_len);
	if (rc < 0) {
		printf("Error in accept [%m]\n");

		goto out;
	}

	client_vsock_fd = rc;

	/*
	 * Read the heartbeat value that the init process in the enclave sends
	 * after vsock connect.
	 */
	rc = read(client_vsock_fd, &recv_buf, sizeof(recv_buf));
	if (rc < 0) {
		printf("Error in read [%m]\n");

		goto out;
	}

	if (rc != sizeof(recv_buf) || recv_buf != NE_IMAGE_LOAD_HEARTBEAT_VALUE) {
		printf("Read %d instead of %d\n", recv_buf,
		       NE_IMAGE_LOAD_HEARTBEAT_VALUE);

		goto out;
	}

	/* Write the heartbeat value back. */
	rc = write(client_vsock_fd, &recv_buf, sizeof(recv_buf));
	if (rc < 0) {
		printf("Error in write [%m]\n");

		goto out;
	}

	rc = 0;

out:
	close(server_vsock_fd);

	return rc;
}

static void check_opts(const char *opt)
{
	if (!strncmp(opt, "image=", 6)) {
		eif_image = strdup(opt + 6);
		printf("NE image path: %s\n", eif_image);
	} else if (strstr(opt, "memory")) {
		ne_mem_regions = atoi(strchr(opt, '=') + 1);
		printf("NE memory regions: %d\n", ne_mem_regions);
	} else if (strstr(opt, "vcpus")) {
		ne_vcpu_nums = atoi(strchr(opt, '=') + 1);
		printf("NE vcpus: %d\n", ne_vcpu_nums);
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

int pal_get_version()
{
	return PAL_VERSION;
}

int pal_init(const struct pal_attr_t *attr)
{
	unsigned int i = 0;
	int ne_dev_fd = -1;
	int rc = -EINVAL;
	unsigned long slot_uid = 0;

	printf("attr->args=[%s]\n", attr->args);
	parse_args(attr->args);

	ne_dev_fd = open(NE_DEV_NAME, O_RDWR | O_CLOEXEC);
	if (ne_dev_fd < 0) {
		printf("Error in open NE device [%m]\n");

		exit(EXIT_FAILURE);
	}

	printf("Creating enclave slot ...\n");

	rc = ne_create_vm(ne_dev_fd, &slot_uid, &enclave_fd);

	close(ne_dev_fd);

	if (rc < 0)
		exit(EXIT_FAILURE);

	printf("Enclave fd %d\n", enclave_fd);

	for (i = 0; i < ne_mem_regions; i++) {
		ne_user_mem_regions[i].memory_size = NE_MIN_MEM_REGION_SIZE;

		rc = ne_alloc_user_mem_region(&ne_user_mem_regions[i]);
		if (rc < 0) {
			printf("Error in alloc userspace memory region, iter %d\n", i);

			goto release_enclave_fd;
		}
	}

	printf("Enclave memory regions were alloced\n");

	return 0;

release_enclave_fd:
	close(enclave_fd);
	ne_free_mem_regions(ne_user_mem_regions);
	return -1;
}

int pal_create_process(struct pal_create_process_args *args)
{
	pthread_t thread_id = 0;
	unsigned int ne_vcpus[NE_DEFAULT_NR_VCPUS] = { };
	unsigned int i = 0;
	int rc = -EINVAL;

	printf("pal_create_process: args->argv[0]=[%s]\n", args->argv[0]);

	rc = pthread_create(&thread_id, NULL, ne_poll_enclave_fd,
			    (void *) &enclave_fd);
	if (rc < 0) {
		printf("Error in thread create [%m]\n");

		goto release_enclave_fd;
	}

	rc = ne_load_enclave_image(enclave_fd, ne_user_mem_regions, eif_image);
	if (rc < 0) {
		printf("Error in load enclave image [%m]\n");

		goto release_enclave_fd;
	}

	printf("Enclave image was loaded\n");

	for (i = 0; i < ne_mem_regions; i++) {
		rc = ne_set_user_mem_region(enclave_fd, ne_user_mem_regions[i]);
		if (rc < 0) {
			printf("Error in set memory region, iter %d\n", i);

			goto release_enclave_fd;
		}
	}

	printf("Enclave memory regions were added\n");

	for (i = 0; i < ne_vcpu_nums; i++) {
		/*
		 * The vCPU is chosen from the enclave vCPU pool, if the value
		 * of the vcpu_id is 0.
		 */
		ne_vcpus[i] = 0;
		rc = ne_add_vcpu(enclave_fd, &ne_vcpus[i]);
		if (rc < 0) {
			printf("Error in add vcpu, iter %d\n", i);

			goto release_enclave_fd;
		}

		printf("Added vCPU %d to the enclave\n", ne_vcpus[i]);
	}

	printf("Enclave vCPUs were added\n");

	rc = ne_start_enclave_check_booted(enclave_fd);
	if (rc < 0) {
		printf("Error in the enclave start / image loading heartbeat logic [rc=%d]\n", rc);

		goto release_enclave_fd;
	}

	return 0;

release_enclave_fd:
	close(enclave_fd);
	ne_free_mem_regions(ne_user_mem_regions);
	return -1;
}

int pal_exec(struct pal_exec_args *args)
{
	printf("Entering sleep for %d seconds ...\n", NE_SLEEP_TIME);

	sleep(NE_SLEEP_TIME);

	return 0;
}

int pal_kill(int pid, int sig)
{
	//TODO: maybe also call close enclave_fd to release enclave instance
	// close(enclave_fd);
	// ne_free_mem_regions(ne_user_mem_regions);
	return 0;
}

int pal_destroy(void)
{
	close(enclave_fd);
	ne_free_mem_regions(ne_user_mem_regions);
	return 0;
}
