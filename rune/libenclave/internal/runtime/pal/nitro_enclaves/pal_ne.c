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
#include <linux/vm_sockets.h>

#include "ne.h"
#include "pal_ne.h"
#include "nitro_enclaves.h"

/**
 * Nitro Enclave Global Variable
 */
char *eif_image = NULL;
int enclave_fd = -1;
unsigned int ne_vcpu_nums = NE_DEFAULT_NR_VCPUS;
unsigned int ne_mem_regions = NE_DEFAULT_NR_MEM_REGIONS;
struct ne_user_mem_region ne_user_mem_regions[NE_DEFAULT_NR_MEM_REGIONS] = { };

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
	unsigned int ne_vcpus[NE_DEFAULT_NR_VCPUS] = { };

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

	return 0;

release_enclave_fd:
	ne_free_mem_regions(ne_user_mem_regions);
	close(enclave_fd);
	return -1;
}

int pal_create_process(struct pal_create_process_args *args)
{
	pthread_t thread_id = 0;
	int rc = -EINVAL;

	printf("pal_create_process: args->argv[0]=[%s]\n", args->argv[0]);

	rc = pthread_create(&thread_id, NULL, ne_poll_enclave_fd,
			    (void *) &enclave_fd);
	if (rc < 0) {
		printf("Error in thread create [%m]\n");
		goto release_enclave_fd;
	}

	rc = ne_start_enclave_check_booted(enclave_fd);
	if (rc < 0) {
		printf("Error in the enclave start / image loading heartbeat logic [rc=%d]\n", rc);
		goto release_enclave_fd;
	}

	return 0;

release_enclave_fd:
	ne_free_mem_regions(ne_user_mem_regions);
	close(enclave_fd);
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
	// TODO: maybe also call close enclave_fd to release enclave instance
	return 0;
}

int pal_destroy(void)
{
	ne_free_mem_regions(ne_user_mem_regions);
	close(enclave_fd);
	return 0;
}
