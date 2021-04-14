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

#define ENCLAVE_FILENAME "sgx_stub_enclave.signed.so"

static sgx_enclave_id_t load_enclave(void)
{
	sgx_launch_token_t t;

	memset(t, 0, sizeof(t));

	sgx_enclave_id_t eid;
	int updated = 0;
	int ret = sgx_create_enclave(ENCLAVE_FILENAME, 1, &t, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		fprintf(stderr, "Failed to create Enclave: error %d\n", ret);
		return -1;
	}

	printf("Success to load enclave id %ld\n", eid);

	return eid;
}
#endif

int ra_tls_server_startup(int connd, enclave_tls_log_level_t log_level,
			  char *attester_type, char *verifier_type,
			  char *tls_type, char *crypto_type)
{
	enclave_tls_err_t ret;
	enclave_tls_handle handle;
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
		fprintf(stderr, "ERROR: failed to transmit. %ld, %ld\n", len,
			strnlen(buff, sizeof(buff)));
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

int main(int argc, char **argv)
{
	char *attester_type = "";
	char *verifier_type = "";
	char *tls_type = "";
	char *crypto = "";
	const char *program;
	int opt;

	char *const short_options = "a:v:t:c:";
	struct option long_options[] = {
		{"attester", required_argument, NULL, 'a'},
		{"verifier", required_argument, NULL, 'v'},
		{"tls", required_argument, NULL, 't'},
		{"crypto", required_argument, NULL, 'c'},
		{0, 0, 0, 0}
	};

	program = argv[0];

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
			crypto = optarg;
			break;
		case -1:
			break;
		default:
			exit(1);
		}
	} while (opt != -1);

	int sockfd;
	int connd;
	struct sockaddr_in servAddr;
	struct sockaddr_in clientAddr;
	socklen_t size = sizeof(clientAddr);

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Failed to create the socket.");
		return -1;
	}

	int ret = 0;
	int reuse = 1;
	ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
			 (const void *) &reuse, sizeof(int));
	if (ret < 0) {
		perror("setsockopt");
		return -1;
	}

	/* Initialize the server address struct with zeros */
	memset(&servAddr, 0, sizeof(servAddr));
	/* Fill in the server address */
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servAddr.sin_port = htons(1234);

	/* Bind the server socket */
	if (bind(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) == -1) {
		perror("Failed to bind.");
		return -1;
	}

	/* Listen for a new connection, allow 5 pending connections */
	if (listen(sockfd, 5) == -1) {
		perror("Failed to listen.");
		return -1;
	}

	printf("Waiting for a connection...\n");

	/* Accept client connections */
	if ((connd = accept(sockfd, (struct sockaddr *) &clientAddr, &size)) == -1) {
		perror("Failed to accept the connection.");
		return -1;
	}

	ra_tls_server_startup(connd, ENCLAVE_TLS_LOG_LEVEL_DEBUG, attester_type,
			      verifier_type, tls_type, crypto);

	return 0;
}
