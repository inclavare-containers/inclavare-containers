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
#include <sgx_urts.h>
#include <sgx_quote.h>
#include <enclave-tls/api.h>

#define ENCLAVE_FILENAME "sgx_stub_enclave.signed.so"

static sgx_enclave_id_t load_enclave(void)
{
        sgx_launch_token_t t;
        memset(t, 0, sizeof(t));

        sgx_enclave_id_t id;
        int updated = 0;
        int ret = sgx_create_enclave(ENCLAVE_FILENAME, 1, &t, &updated, &id, NULL);
        if (ret != SGX_SUCCESS) {
                fprintf(stderr, "Failed to create Enclave: error %d\n", ret);
                return -1;
        }

        return id;
}

int ra_tls_echo(int sockfd, enclave_tls_log_level_t log_level,
		char *attester_type, char *verifier_type, char *tls_type,
		char *crypto)
{
	enclave_tls_err_t ret;
	enclave_tls_handle handle;
	enclave_tls_conf_t conf;

	memset(&conf, 0, sizeof(conf));
	conf.log_level = log_level;
	strcpy(conf.attester_type, attester_type);
	strcpy(conf.verifier_type, verifier_type);
	strcpy(conf.tls_type, tls_type);
	strcpy(conf.crypto_type, crypto);
	conf.eid = load_enclave();

	ret = enclave_tls_init(&conf, &handle);
	if (ret != ENCLAVE_TLS_ERR_NONE || !handle) {
		fprintf(stderr, "ERROR: failed to initialization.\n");
	}

	ret = enclave_tls_negotiate(handle, sockfd);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "ERROR: failed to negotiate.\n");
		goto err;
	}

	const char *http_request = "GET / HTTP/1.0\r\n\r\n";
	size_t len = strlen(http_request);
	ret = enclave_tls_transmit(handle, (void *) http_request, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE || len != strlen(http_request)) {
		fprintf(stderr, "ERROR: failed to transmit.\n");
		goto err;
	}

	char buff[256];
	memset(buff, 0, sizeof(buff));
	len = sizeof(buff) - 1;
	ret = enclave_tls_receive(handle, buff, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "ERROR: failed to receive.\n");
		goto err;
	}
	printf("Server:\n%s\n", buff);

	ret = enclave_tls_cleanup(handle);
        if (ret != ENCLAVE_TLS_ERR_NONE) {
                fprintf(stderr, "ERROR: failed to cleanup.\n");
        }
	return 0;	

err:
	enclave_tls_cleanup(handle);
	return -1;
}
