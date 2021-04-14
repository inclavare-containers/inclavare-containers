#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <enclave-tls/api.h>

#define DEFAULT_PORT 1234

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

int ra_tls_echo(int sockfd, enclave_tls_log_level_t log_level,
		char *attester_type, char *verifier_type, char *tls_type,
		char *crypto_type)
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
	struct sockaddr_in servAddr;
	char buff[256];
	size_t len;

	/* Create a socket that uses an internet IPv4 address,
	 * Sets the socket to be stream based (TCP),
	 * 0 means choose the default protocol. */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "ERROR: failed to create the socket\n");
		return -1;
	}

	/* Initialize the server address struct with zeros */
	memset(&servAddr, 0, sizeof(servAddr));

	/* Fill in the server address */
	servAddr.sin_family = AF_INET;	/* using IPv4      */
	servAddr.sin_port = htons(DEFAULT_PORT);	/* on DEFAULT_PORT */

	const char *srvaddr = "127.0.0.1";

	/* Get the server IPv4 address from the command line call */
	if (inet_pton(AF_INET, srvaddr, &servAddr.sin_addr) != 1) {
		fprintf(stderr, "ERROR: invalid address\n");
		return -1;
	}

	/* Connect to the server */
	if (connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) == -1) {
		fprintf(stderr, "ERROR: failed to connect\n");
		return -1;
	}

	ra_tls_echo(sockfd, ENCLAVE_TLS_LOG_LEVEL_DEBUG, attester_type,
		    verifier_type, tls_type, crypto);

	return 0;
}
