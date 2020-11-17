#include "App.h" /* contains include of Enclave_u.h which has wolfSSL header files */
#include "assert.h"
#include <wolfssl/ssl.h>
//#include <wolfssl/certs_test.h>
#include <sys/time.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#define MAX_PATH		4096
#define ENCLAVE_FILENAME	"Wolfssl_Enclave.signed.so"
#define PAL_VERSION		3

/* Use Debug SGX ? */
#if _DEBUG
	#define DEBUG_VALUE SGX_DEBUG_FLAG
#else
	#define DEBUG_VALUE 1
#endif

static sgx_enclave_id_t global_eid = SGX_ERROR_INVALID_ENCLAVE_ID;
static unsigned int num = 0;

typedef struct pal_attr {
	const char *instance_dir;
	const char *log_level;
} pal_attr_t;

struct pal_stdio_fds {
	int stdin, stdout, stderr;
};

struct pal_create_process_args {
	const char *path;
	const char **argv;
	const char **env;
	const struct occlum_stdio_fds *stdio;
	int *pid;
};

struct pal_exec_args {
	int pid;
	int *exit_value;
};

static sgx_enclave_id_t get_enclave_id(void) {
	return global_eid;
}

static const char *get_enclave_absolute_path(const char *instance_dir)
{
	static char enclave_path[MAX_PATH + 1] = {0};

	strncat(enclave_path, instance_dir, MAX_PATH);
	strncat(enclave_path, "/", MAX_PATH);
	strncat(enclave_path, ENCLAVE_FILENAME, MAX_PATH);
	return (const char *)enclave_path;
}

int pal_get_version(void)
{
	return PAL_VERSION;
}

int pal_init(const pal_attr_t *attr)
{
	errno = 0;

	if (get_enclave_id() != SGX_ERROR_INVALID_ENCLAVE_ID) {
		errno = EINVAL;
		PAL_ERROR("Enclave runtime has been initialized!");
		return -1;
	}

	if (!attr) {
		errno = EINVAL;
		return -1;
	}

	if (!attr->instance_dir) {
		errno = EINVAL;
		return -1;
	}

	PAL_DEBUG("attr->instance_dir = %s", attr->instance_dir);

	sgx_launch_token_t t;
	memset(t, 0, sizeof(sgx_launch_token_t));

	const char *enclave_path = get_enclave_absolute_path(attr->instance_dir);
	PAL_DEBUG("enclave_path = %s", enclave_path);

	sgx_enclave_id_t id;
	int updated = 0;
	int ret = sgx_create_enclave(enclave_path, DEBUG_VALUE, &t, &updated, &id, NULL);
	if (ret != SGX_SUCCESS) {
		PAL_ERROR("Failed to create Enclave: error %d.", ret);
		return -1;
	}

	global_eid = id;

	return 0;
}

int pal_create_process(struct pal_create_process_args *args)
{
	errno = 0;

	if (get_enclave_id() == SGX_ERROR_INVALID_ENCLAVE_ID) {
		errno = EINVAL;
		PAL_ERROR("Enclave runtime uninitialized yet!");
		return -1;
	}

	if (args == NULL || args->path == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (access(args->path, F_OK) != 0)
		return -1;

	if (access(args->path, R_OK) != 0)
		return -1;

	if (!args->stdio) {
		errno = EINVAL;
		return -1;
	}

	if (!args->pid) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int pal_exec(struct pal_exec_args *args)
{
	errno = 0;

	if (get_enclave_id() == SGX_ERROR_INVALID_ENCLAVE_ID) {
		errno = EINVAL;
		PAL_ERROR("enclave runtime sgxsdk uninitialized yet!");
		return -1;
	}

	if (!args || !args->exit_value) {
		errno = EINVAL;
		return -1;
	}

	if (!num) {
		++num;
		while (1) {
			printf("Hello World!\n");
			printf("    - Powered by ACK-TEE and runE\n");
			fflush(stdout);
			sleep(3);
		}
	} else {
		 printf("Hello stub enclave!\n");
		 printf("    - Welcome to stub enclave\n");
	}

	return 0;
}

int pal_destroy(void)
{
	errno = 0;

	if (get_enclave_id() == SGX_ERROR_INVALID_ENCLAVE_ID) {
		errno = EINVAL;
		PAL_ERROR("enclave runtime uninitialized yet!");
		return -1;
	}

	PAL_DEBUG("enclave runtime sgxsdk exits");

	return 0;
}

int pal_get_local_report(void *targetinfo, int targetinfo_len, void *report, int *report_len)
{
	errno = 0;

	sgx_enclave_id_t eid = get_enclave_id();
	if (eid == SGX_ERROR_INVALID_ENCLAVE_ID) {
		errno = EINVAL;
		PAL_ERROR("Enclave runtime has not been initialized!");
		return -1;
	}

	if (!targetinfo || targetinfo_len != sizeof(sgx_target_info_t)) {
		errno = EINVAL;
		PAL_ERROR("Input parameter targetinfo is NULL or targentinfo_len is not enough!");
		return -1;
	}

	if (!report || !report_len || *report_len < sizeof(sgx_report_t)) {
		errno = EINVAL;
		PAL_ERROR("Input parameter report is NULL or report_len is not enough!");
		return -1;
	}

	int ret;
	int sgxStatus;
	sgxStatus = enc_wolfSSL_Init(eid, &ret);
	if (sgxStatus != SGX_SUCCESS || ret != WOLFSSL_SUCCESS)
		return -1;

#ifdef SGX_DEBUG
	enc_wolfSSL_Debugging_ON(eid);
#else
	enc_wolfSSL_Debugging_OFF(eid);
#endif

	WOLFSSL_METHOD *method;
	sgxStatus = enc_wolfTLSv1_2_server_method(eid, &method);
	if (sgxStatus != SGX_SUCCESS || !method) {
		PAL_ERROR("wolfTLSv1_2_server_method failure");
		return -1;
	}

	WOLFSSL_CTX *ctx;
	sgxStatus = enc_wolfSSL_CTX_new(eid, &ctx, method);
	if (sgxStatus != SGX_SUCCESS || !ctx) {
		PAL_ERROR("wolfSSL_CTX_new failure");
		return -1;
	}

	sgxStatus = enc_create_key_and_x509(eid, &ret, ctx, targetinfo, report);
	if (sgxStatus != SGX_SUCCESS || ret != SGX_SUCCESS ) {
		PAL_ERROR("enc_create_key_and_x509 failure");
		return EXIT_FAILURE;
	}

#if 0
	/* Load server certificates into WOLFSSL_CTX */
	sgxStatus = enc_wolfSSL_CTX_use_certificate_buffer(eid, &ret, ctx,
		server_cert_der_2048, sizeof_server_cert_der_2048, SSL_FILETYPE_ASN1);
	if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
		PAL_ERROR("enc_wolfSSL_CTX_use_certificate_chain_buffer_format failure");
		return -1;
	}

	/* Load server key into WOLFSSL_CTX */
	sgxStatus = enc_wolfSSL_CTX_use_PrivateKey_buffer(eid, &ret, ctx,
		server_key_der_2048, sizeof_server_key_der_2048, SSL_FILETYPE_ASN1);
	if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
		PAL_ERROR("wolfSSL_CTX_use_PrivateKey_buffer failure");
		return -1;
	}
#endif

	*report_len = sizeof(sgx_report_t);

	enc_wolfSSL_CTX_free(eid, ctx);
	enc_wolfSSL_Cleanup(eid, &ret);

	return ret;
}

static double current_time()
{
	struct timeval tv;
	gettimeofday(&tv,NULL);

	return (double)(1000000 * tv.tv_sec + tv.tv_usec)/1000000.0;
}

void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate 
	 * the input string to prevent buffer overflow.
	 */
	printf("%s", str);
}

void ocall_current_time(double* time)
{
	if(!time) 
		return;
	*time = current_time();
	return;
}

void ocall_low_res_time(int *time)
{
	if(!time) 
		return;

	struct timeval tv;
	*time = tv.tv_sec;

	return;
}

size_t ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
	return recv(sockfd, buf, len, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
	return send(sockfd, buf, len, flags);
}
