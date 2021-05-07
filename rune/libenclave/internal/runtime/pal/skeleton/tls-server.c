#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sgx_urts.h>
#include <sgx_quote.h>
#include <enclave-tls/api.h>
#include "tls-server.h"

#define ENCLAVE_FILENAME "sgx_stub_enclave.signed.so"
#define ENCLAVE_TLS_HELLO "Hello and welcome to Enclave TLS!\n"

extern sgx_status_t ecall_generate_evidence(sgx_enclave_id_t eid, sgx_status_t *retval, uint8_t *hash, sgx_report_t *report);

static sgx_enclave_id_t load_enclave(void)
{
	sgx_launch_token_t t;

	memset(t, 0, sizeof(t));

	sgx_enclave_id_t eid;
	int updated = 0;
	int ret = sgx_create_enclave(ENCLAVE_FILENAME, 1, &t, &updated, &eid,
				     NULL);
	if (ret != SGX_SUCCESS) {
		fprintf(stderr, "Failed to create Enclave: error %d\n", ret);
		return -1;
	}

	printf("Success to load enclave id %ld\n", eid);

	return eid;
}

int ra_tls_server_startup(int connd)
{
	enclave_tls_conf_t conf;

	memset(&conf, 0, sizeof(conf));

	conf.log_level = ENCLAVE_TLS_LOG_LEVEL_DEFAULT;
	if (debugging)
		conf.log_level = ENCLAVE_TLS_LOG_LEVEL_DEBUG;

	strcpy(conf.attester_type, attester_type);
	strcpy(conf.verifier_type, verifier_type);
	strcpy(conf.tls_type, tls_type);
	strcpy(conf.crypto_type, crypto);
	conf.enclave_id = load_enclave();
	conf.flags |= ENCLAVE_TLS_CONF_FLAGS_SERVER;

	enclave_tls_handle handle;
	enclave_tls_err_t ret = enclave_tls_init(&conf, &handle);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "ERROR: failed to initialization.\n");
		return -1;
	}

	ret = enclave_tls_negotiate(handle, connd);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "ERROR: failed to negotiate.\n");
		goto err;
	}

	printf("Client connected successfully\n");

	char buff[256];
	size_t len = sizeof(buff) - 1;
	memset(buff, 0, sizeof(buff));
	ret = enclave_tls_receive(handle, buff, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "ERROR: failed to receive.\n");
		goto err;
	}

	printf("Client: %s\n", buff);

	/* Obtain the mrenclave and mrsigner of enclave */
	uint8_t hash[SHA256_HASH_SIZE];
	sgx_report_t app_report;
	sgx_status_t generate_evidence_ret;
	sgx_status_t status = ecall_generate_evidence(conf.enclave_id, &generate_evidence_ret, hash, &app_report);
	if (status != SGX_SUCCESS || generate_evidence_ret != SGX_SUCCESS) {
		printf("ecall_generate_evidence() %#x\n", generate_evidence_ret);
		goto err;
	}

	/* Write our reply into buff, reply contains mrencalve, mesigner and hello message */
	memset(buff, 0, sizeof(buff));
	memcpy(buff, &app_report.body.mr_enclave, sizeof(sgx_measurement_t));
	memcpy(buff + sizeof(sgx_measurement_t), &app_report.body.mr_signer, sizeof(sgx_measurement_t));
	memcpy(buff + 2 * sizeof(sgx_measurement_t), ENCLAVE_TLS_HELLO, sizeof(ENCLAVE_TLS_HELLO));

	len = 2 * sizeof(sgx_measurement_t) + sizeof(ENCLAVE_TLS_HELLO);

	/* Reply back to the client */
	ret = enclave_tls_transmit(handle, buff, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE || len != 2 * sizeof(sgx_measurement_t) + sizeof(ENCLAVE_TLS_HELLO)) {
		fprintf(stderr, "ERROR: failed to transmit. %ld, %ld\n", len,
			2 * sizeof(sgx_measurement_t) + sizeof(ENCLAVE_TLS_HELLO));
		goto err;
	}

	ret = enclave_tls_cleanup(handle);
	if (ret != ENCLAVE_TLS_ERR_NONE)
		fprintf(stderr, "ERROR: failed to cleanup.\n");

	return 0;

err:
	enclave_tls_cleanup(handle);
	return -1;
}

int ra_tls_server(void)
{
	printf("    - Welcome to tls server\n");

	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Failed to create the socket.");
		return -1;
	}

	int ret = 0;
	int reuse = 1;
	ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *) &reuse, sizeof(int));
	if (ret < 0) {
		perror("setsockopt");
		return -1;
	}

	struct sockaddr_in servAddr;
	/* Initialize the server address struct with zeros */
	memset(&servAddr, 0, sizeof(servAddr));
	/* Fill in the server address */
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servAddr.sin_port = htons(1234);

	/* Bind the server socket */
	if (bind(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr)) == -1) {
		perror("Failed to bind.");
		goto err;
	}

	/* Listen for a new connection, allow 5 pending connections */
	if (listen(sockfd, 5) == -1) {
		perror("Failed to listen.");
		goto err;
	}

	/* Accept client connections */
	int connd;
	struct sockaddr_in clientAddr;
	socklen_t size = sizeof(clientAddr);
	if ((connd = accept(sockfd, (struct sockaddr *)&clientAddr, &size)) == -1) {
		perror("Failed to accept the connection.");
		goto err;
	}

	if (ra_tls_server_startup(connd) == -1) {
		perror("Failed to start up the server.");
		goto err;
	}

	return 0;

err:
	close(sockfd);
	return -1;
}
