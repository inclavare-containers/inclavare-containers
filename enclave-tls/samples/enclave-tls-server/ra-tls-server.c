#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <enclave-tls/api.h>

int ra_tls_server_startup(int connd, enclave_tls_log_level_t log_level,
			  char *attester_type, char *verifier_type,
			  char *tls_type)
{
	enclave_tls_err_t ret;
	enclave_tls_handle handle;
	enclave_tls_conf_t conf;
	
	memset(&conf, 0, sizeof(conf));
	conf.log_level = log_level;
	strcpy(conf.attester_type, attester_type);
	strcpy(conf.verifier_type, verifier_type);
	strcpy(conf.tls_type, tls_type);
	conf.flags |= ENCLAVE_TLS_CONF_FLAGS_SERVER;

	ret = enclave_tls_init(&conf, &handle);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "ERROR: failed to initialization.\n");
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
	memcpy(buff, "I hear ya fa shizzle!\n", sizeof(buff));
	len = strnlen(buff, sizeof(buff));

	/* Reply back to the client */
	ret = enclave_tls_transmit(handle, buff, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE || len != strnlen(buff, sizeof(buff))) {
		fprintf(stderr, "ERROR: failed to transmit. %ld, %ld\n",len, strnlen(buff, sizeof(buff)));
		goto err;
	}

	ret = enclave_tls_cleanup(handle);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
                fprintf(stderr, "ERROR: failed to cleanup.\n");
        }
	return 0;

err:
	enclave_tls_cleanup(handle);
	return -1;
}
