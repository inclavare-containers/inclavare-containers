#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <enclave-tls/api.h>

#define MRENCLAVE_SIZE 32
#define TLSBUF_MAXLENGHT 2048

int ra_tls_echo(int sockfd, enclave_tls_log_level_t log_level,
		char *attester_type, char *verifier_type, char *tls_type,
		char *crypto, bool mutual)
{
	enclave_tls_conf_t conf;

	memset(&conf, 0, sizeof(conf));
	conf.log_level = log_level;
	strcpy(conf.attester_type, attester_type);
	strcpy(conf.verifier_type, verifier_type);
	strcpy(conf.tls_type, tls_type);
	strcpy(conf.crypto_type, crypto);

	if (mutual)
		conf.flags |= ENCLAVE_TLS_CONF_FLAGS_MUTUAL;

	enclave_tls_handle handle;
	enclave_tls_err_t ret = enclave_tls_init(&conf, &handle);
	if (ret != ENCLAVE_TLS_ERR_NONE || !handle) {
		fprintf(stderr, "ERROR: failed to initialization.\n");
		return -1;
	}

	ret = enclave_tls_negotiate(handle, sockfd);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "ERROR: failed to negotiate.\n");
		goto err;
	}

	const char *http_request = "GET / HTTP/1.1\r\n\r\n";
	size_t len = strlen(http_request);
	ret = enclave_tls_transmit(handle, (void *)http_request, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE || len != strlen(http_request)) {
		fprintf(stderr, "ERROR: failed to transmit.\n");
		goto err;
	}

	char buf[TLSBUF_MAXLENGHT];
	memset(buf, 0, sizeof(buf));
	len = sizeof(buf) - 1;
	ret = enclave_tls_receive(handle, buf, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "ERROR: failed to receive.\n");
		goto err;
	}

	if (len >= sizeof(buf)) 
		len = sizeof(buf) - 1;
	buf[len] = '\0';
	printf("Server:\n%s\n", buf);

	ret = enclave_tls_cleanup(handle);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "ERROR: failed to cleanup.\n");
		goto err;
	}

	return 0;
err:
	enclave_tls_cleanup(handle);
	return -1;
}
