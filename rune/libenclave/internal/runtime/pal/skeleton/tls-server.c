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

#define DEFAULT_ADDRESS "/run/enclave-tls/tls.sock"
#define ENCLAVE_FILENAME "sgx_stub_enclave.signed.so"

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

	/* Write our reply into buff */
	memset(buff, 0, sizeof(buff));
	strcpy(buff, "Hello and welcome to enclave-tls!\n");
	len = strnlen(buff, sizeof(buff));

	/* Reply back to the client */
	ret = enclave_tls_transmit(handle, buff, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE || len != strnlen(buff, sizeof(buff))) {
		fprintf(stderr, "ERROR: failed to transmit. %ld, %ld\n", len,
			strnlen(buff, sizeof(buff)));
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
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("Failed to create the socket.");
		return -1;
	}

	struct sockaddr_un serv_addr;
	/* Initialize the server address struct with zeros */
	memset(&serv_addr, 0, sizeof(serv_addr));
	/* Fill in the server address */
	serv_addr.sun_family = AF_UNIX;
	strncpy(serv_addr.sun_path, DEFAULT_ADDRESS,
		sizeof(serv_addr.sun_path) - 1);

	/* Bind the server socket */
	unlink(DEFAULT_ADDRESS);
	/* *INDENT-OFF* */
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1) {
		perror("Failed to bind.");
		goto err;
	}
	/* *INDENT-ON* */

	/* Listen for a new connection, allow 5 pending connections */
	if (listen(sockfd, 5) == -1) {
		perror("Failed to listen.");
		goto err;
	}

	/* Accept client connections */
	int connd;
	if ((connd = accept(sockfd, NULL, NULL)) == -1) {
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
