#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <enclave-tls/api.h>

#ifndef OCCLUM
#include <sgx_urts.h>
#include <sgx_quote.h>

#define ENCLAVE_FILENAME     "sgx_stub_enclave.signed.so"

static sgx_enclave_id_t load_enclave(void)
{
	sgx_launch_token_t t;

	memset(t, 0, sizeof(t));

	sgx_enclave_id_t eid;
	int updated = 0;
	int ret = sgx_create_enclave(ENCLAVE_FILENAME, 1, &t, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		fprintf(stderr, "Failed to create enclave %d\n", ret);
		return -1;
	}

	printf("Success to load enclave id %ld\n", eid);

	return eid;
}
#endif

int enclave_tls_server_startup(int fd, enclave_tls_log_level_t log_level,
			       char *attester_type, char *verifier_type,
			       char *tls_type, char *crypto_type)
{
	enclave_tls_conf_t conf;

	memset(&conf, 0, sizeof(conf));
	conf.log_level = log_level;
	strcpy(conf.attester_type, attester_type);
	strcpy(conf.verifier_type, verifier_type);
	strcpy(conf.tls_type, tls_type);
	strcpy(conf.crypto_type, crypto_type);
#ifndef OCCLUM
	conf.enclave_id = load_enclave();
#endif
	conf.flags |= ENCLAVE_TLS_CONF_FLAGS_SERVER;

	enclave_tls_handle handle;
	enclave_tls_err_t ret = enclave_tls_init(&conf, &handle);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "failed to initialize enclave tls %#x\n", ret);
		return -1;
	}

	ret = enclave_tls_negotiate(handle, fd);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "failed to negotiate %#x\n", ret);
		goto err;
	}

	printf("Client connected successfully\n");

	char buf[256];
	size_t len = sizeof(buf);
	ret = enclave_tls_receive(handle, buf, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "failed to receive %#x\n", ret);
		goto err;
	}

	if (len >= sizeof(buf))
		len = sizeof(buf) - 1;
	buf[len] = '\0';

	printf("Client: %s\n", buf);

	/* Reply back to the client */
	ret = enclave_tls_transmit(handle, buf, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "failed to transmit %#x\n", ret);
		goto err;
	}

err:
	ret = enclave_tls_cleanup(handle);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "failed to cleanup %#x\n", ret);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	char *const short_options = "a:v:t:c:";
	struct option long_options[] = {
		{"attester", required_argument, NULL, 'a'},
		{"verifier", required_argument, NULL, 'v'},
		{"tls", required_argument, NULL, 't'},
		{"crypto", required_argument, NULL, 'c'},
		{0, 0, 0, 0}
	};

	char *attester_type = "";
	char *verifier_type = "";
	char *tls_type = "";
	char *crypto_type = "";
	int opt;

	do {
		opt = getopt_long(argc, argv, short_options, long_options,
				  NULL);
		switch (opt) {
		case 'a':
			attester_type = optarg;
			break;
		case 'v':
			verifier_type = optarg;
			break;
		case 't':
			tls_type = optarg;
			break;
		case 'c':
			crypto_type = optarg;
			break;
		case -1:
			break;
		default:
			exit(1);
		}
	} while (opt != -1);

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("Failed to call socket()");
		return -1;
	}

	int reuse = 1;
	int ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
			     (const void *)&reuse, sizeof(int));
	if (ret < 0) {
		perror("Failed to call setsockopt()");
		return -1;
	}

	struct sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	s_addr.sin_port = htons(1234);

	/* Bind the server socket */
	if (bind(sockfd, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1) {
		perror("Failed to call bind()");
		return -1;
	}

	/* Listen for a new connection, allow 5 pending connections */
	if (listen(sockfd, 5) == -1) {
		perror("Failed to call listen()");
		return -1;
	}

	printf("Waiting for a connection ...\n");

	/* Accept client connections */
	struct sockaddr_in c_addr;
	socklen_t size = sizeof(c_addr);
	int connd = accept(sockfd, (struct sockaddr *)&c_addr, &size);
	if (connd < 0) {
		perror("Failed to call accept()");
		return -1;
	}

	return enclave_tls_server_startup(connd, ENCLAVE_TLS_LOG_LEVEL_DEBUG,
					  attester_type, verifier_type,
					  tls_type, crypto_type);
}
