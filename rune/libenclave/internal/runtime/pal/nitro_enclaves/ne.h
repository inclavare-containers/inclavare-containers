/* *INDENT-OFF* */
#ifndef NE_H
#define NE_H
/* *INDENT-ON* */

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
int ne_create_vm(int ne_dev_fd, unsigned long *slot_uid, int *enclave_fd);

/**
 * ne_alloc_user_mem_region() - Allocate a user space memory region for an enclave.
 * @ne_user_mem_region:	User space memory region allocated using hugetlbfs.
 *
 * Context: Process context.
 * Return:
 * * 0 on success.
 * * Negative return value on failure.
 */
int ne_alloc_user_mem_region(struct ne_user_mem_region *ne_user_mem_region);

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
int ne_set_user_mem_region(int enclave_fd,
			   struct ne_user_mem_region ne_user_mem_region);

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
int ne_add_vcpu(int enclave_fd, unsigned int *vcpu_id);

/**
 * ne_poll_enclave_fd() - Thread function for polling the enclave fd.
 * @data:	Argument provided for the polling function.
 *
 * Context: Process context.
 * Return:
 * * NULL on success / failure.
 */
void *ne_poll_enclave_fd(void *data);

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
int ne_load_enclave_image(int enclave_fd,
			  struct ne_user_mem_region
			  ne_user_mem_regions[], char *enclave_image_path);

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
int ne_start_enclave_check_booted(int enclave_fd);

/**
 * ne_free_mem_regions() - Unmap all the user space memory regions that were set
 *			   aside for the enclave.
 * @ne_user_mem_regions:	The user space memory regions associated with an enclave.
 *
 * Context: Process context.
 */
void ne_free_mem_regions(struct ne_user_mem_region ne_user_mem_regions[]);

/* *INDENT-OFF* */
#endif /* NE_H */
/* *INDENT-ON* */
