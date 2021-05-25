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

int ra_tls_echo(int sockfd, enclave_tls_log_level_t log_level,  \
                char *attester_type, char *verifier_type, char *tls_type,  \
                char *crypto, bool mutual, unsigned char *sendmsg, unsigned int sendmsglen, unsigned char *retmsg, unsigned int *recemsglen)
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

	size_t len = 0;
	len = (size_t)sendmsglen;
	ret = enclave_tls_transmit(handle, sendmsg, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE || len != strlen(sendmsg)) {
		fprintf(stderr, "ERROR: failed to transmit.\n");
		goto err;
	}

	len = TLSBUF_MAXLENGHT - 1;
	ret = enclave_tls_receive(handle, retmsg, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "ERROR: failed to receive.\n");
		goto err;
	}

	if (len >= TLSBUF_MAXLENGHT) 
		len = TLSBUF_MAXLENGHT - 1;
	printf("Server:\n%s\n", retmsg);
	*recemsglen = len;

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
