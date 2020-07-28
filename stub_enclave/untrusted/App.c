#include "App.h" /* contains include of Enclave_u.h which has wolfSSL header files */
#include "assert.h"
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>
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
static bool initialized = false;
static unsigned int num = 0;

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

const char* get_enclave_absolute_path(char* instance_dir) {
	static char enclave_path[MAX_PATH + 1] = {0};
	strncat(enclave_path, instance_dir, MAX_PATH);
	strncat(enclave_path, "/", MAX_PATH);
	strncat(enclave_path, ENCLAVE_FILENAME, MAX_PATH);
	return (const char*)enclave_path;
}

int pal_get_version(void) {
    return PAL_VERSION;
}

int pal_init(const sgxsdk_pal_attr_t* attr) {
	errno = 0;

	if (attr == NULL) {
		return -EINVAL;
	}

	if (attr->instance_dir == NULL) {
		return -EINVAL;
	}

	PAL_INFO("attr->instance_dir = %s", attr->instance_dir);
	sgx_enclave_id_t eid = pal_get_enclave_id();
	if (eid != SGX_ERROR_INVALID_ENCLAVE_ID) {
		PAL_ERROR("Enclave has been initialized.");
		return -EEXIST;
	}

	sgx_enclave_id_t id;
	sgx_launch_token_t t;

	int ret = 0;
	int updated = 0;

	memset(t, 0, sizeof(sgx_launch_token_t));

	char * enclave_path = get_enclave_absolute_path(attr->instance_dir);
	PAL_INFO("enclave_path = %s", enclave_path);

	ret = sgx_create_enclave(enclave_path, DEBUG_VALUE, &t, &updated, &id, NULL);
	if (ret != SGX_SUCCESS) {
		PAL_ERROR("Failed to create Enclave : error %d - %#x.", ret, ret);
		return ret;
	}

	global_eid = id;
	initialized = true;
}

int pal_create_process(struct pal_create_process_args *args)
{
	if (args->path == NULL || access(args->path, F_OK) != 0)
		return -ENOENT;	

	if (access(args->path, R_OK) != 0)
		return -EACCES;

	if (!args->stdio)
		return -EINVAL;

	if (!args->pid)
		return -EINVAL;

	if (!initialized) {
		PAL_ERROR("enclave runtime sgxsdk uninitialized yet!");
		return -EINVAL;
	}

	return 0;
}

int pal_exec(struct pal_exec_args *args){
	if (args->exit_value == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (num == 0) {
		num ++;
		while(1) {
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
	if (!initialized) {
		PAL_ERROR("enclave runtime sgxsdk uninitialized yet!");
		return -1;
	}

	PAL_INFO("enclave runtime sgxsdk exits");
	return 0;
}

int pal_get_local_report(void *targetinfo, int targetinfo_len, void *report, int* report_len) {
	/* 0. check the args */
	if (!initialized) {
		PAL_ERROR("enclave runtime sgxsdk uninitialized yet!");
	}

	if (targetinfo == NULL || targetinfo_len != sizeof(sgx_target_info_t)) {
		PAL_ERROR("Input parameter targetinfo is NULL or targentinfo_len is not enough!");
		return -EINVAL;
	}

	if (report == NULL || report_len == NULL || *report_len < sizeof(sgx_report_t)) {
		PAL_ERROR("Input parameter report is NULL or report_len is not enough!");
		return -EINVAL;
	}

	sgx_enclave_id_t eid = pal_get_enclave_id();
	if (eid == SGX_ERROR_INVALID_ENCLAVE_ID) {
		PAL_ERROR("Enclave has not been initialized!");
		return -EINVAL;
	}

	int sgxStatus;
	int ret = 0;
	WOLFSSL_METHOD* method;
	WOLFSSL_CTX*    ctx;

	/* 1. generate mTLS keys and the correspondings hash values */
	/* Initialize wolfSSL */
	enc_wolfSSL_Init(eid, &sgxStatus);

#ifdef SGX_DEBUG
	enc_wolfSSL_Debugging_ON(global_eid);
#else
	enc_wolfSSL_Debugging_OFF(global_eid);
#endif

	sgxStatus = enc_wolfTLSv1_2_server_method(global_eid, &method);
	if (sgxStatus != SGX_SUCCESS || method == NULL) {
		PAL_ERROR("wolfTLSv1_2_server_method failure");
		return EXIT_FAILURE;
	}

	sgxStatus = enc_wolfSSL_CTX_new(global_eid, &ctx, method);
	if (sgxStatus != SGX_SUCCESS || ctx == NULL) {
		PAL_ERROR("wolfSSL_CTX_new failure");
		return EXIT_FAILURE;
	}

	/* Load server certificates into WOLFSSL_CTX */
	sgxStatus = enc_wolfSSL_CTX_use_certificate_buffer(global_eid, &ret, ctx,
		server_cert_der_2048, sizeof_server_cert_der_2048, SSL_FILETYPE_ASN1);
	if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
		PAL_ERROR("enc_wolfSSL_CTX_use_certificate_chain_buffer_format failure");
		return EXIT_FAILURE;
	}

	/* Load server key into WOLFSSL_CTX */
	sgxStatus = enc_wolfSSL_CTX_use_PrivateKey_buffer(global_eid, &ret, ctx,
		server_key_der_2048, sizeof_server_key_der_2048, SSL_FILETYPE_ASN1);
	if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
		PAL_ERROR("wolfSSL_CTX_use_PrivateKey_buffer failure");
		return EXIT_FAILURE;
	}

	sgxStatus = enc_create_key_and_x509(global_eid, &ret, ctx, targetinfo, report);
	if (sgxStatus != SGX_SUCCESS || ret != SGX_SUCCESS ) {
		PAL_ERROR("enc_create_key_and_x509 failure");
		return EXIT_FAILURE;
	}

	/* 3. return report */
	targetinfo_len = sizeof(sgx_target_info_t);
	*report_len = sizeof(sgx_report_t);

	enc_wolfSSL_CTX_free(global_eid, ctx);

	return ret;
}

sgx_enclave_id_t pal_get_enclave_id(void) {
	return global_eid;
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
	*      * the input string to prevent buffer overflow. 
	*           */ 
	printf("%s", str);
}

void ocall_current_time(double* time)
{
	if(!time) 
		return;
	*time = current_time();
	return;
}

void ocall_low_res_time(int* time)
{
	struct timeval tv;
	if(!time) 
		return;
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
