/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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

#ifdef OCCLUM
#include <sgx_report.h>
#else
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
		fprintf(stderr, "Failed to load enclave %d\n", ret);
		return -1;
	}

	printf("Success to load enclave id %ld\n", eid);

	return eid;
}
#endif

int enclave_tls_echo(int fd, enclave_tls_log_level_t log_level,
		     char *attester_type, char *verifier_type,
		     char *tls_type, char *crypto_type, bool mutual)
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
	if (mutual)
		conf.flags |= ENCLAVE_TLS_CONF_FLAGS_MUTUAL;

	enclave_tls_handle handle;
	enclave_tls_err_t ret = enclave_tls_init(&conf, &handle);
	if (ret != ENCLAVE_TLS_ERR_NONE || !handle) {
		fprintf(stderr, "failed to initialize enclave tls %#x\n", ret);
		return -1;
	}

	ret = enclave_tls_negotiate(handle, fd);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "failed to negotiate %#x\n", ret);
		goto err;
	}

	const char *msg = "Hello and welcome to Enclave TLS!\n";
	size_t len = strlen(msg);
	ret = enclave_tls_transmit(handle, (void *)msg, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE || len != strlen(msg)) {
		fprintf(stderr, "failed to transmit %#x\n", ret);
		goto err;
	}

	char buf[256];
	len = sizeof(buf);
	ret = enclave_tls_receive(handle, buf, &len);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "failed to receive %#x\n", ret);
		goto err;
	}

	if (len >= sizeof(buf))
		len = sizeof(buf) - 1;
	buf[len] = '\0';

	/* Server running in SGX Enclave will send mrenclave, mrsigner and hello message to client */
	if (len >= 2 * sizeof(sgx_measurement_t)) {
		printf("Server's SGX identity:\n");
		printf("  . MRENCLAVE = ");
		for (int i = 0; i < 32; ++i)
			printf("%02x", (uint8_t)buf[i]);
		printf("\n");
		printf("  . MRSIGNER  = ");
		for (int i = 32; i < 64; ++i)
			printf("%02x", (uint8_t)buf[i]);
		printf("\n");

		printf("Server:\n%s\n", buf + 2 * sizeof(sgx_measurement_t));
	} else {
		/* Server not running in SGX Enlcave will only send hello message to client */
		printf("Server: %s\n", buf);
	}

err:
	ret = enclave_tls_cleanup(handle);
	if (ret != ENCLAVE_TLS_ERR_NONE) {
		fprintf(stderr, "failed to cleanup %#x\n", ret);
		return -1;
	}

	return ret;
}

int main(int argc, char **argv)
{
	printf("    - Welcome to Enclave-TLS sample client program\n");

	char *const short_options = "a:v:t:c:ml:";
	struct option long_options[] = {
		{"attester", required_argument, NULL, 'a'},
		{"verifier", required_argument, NULL, 'v'},
		{"tls", required_argument, NULL, 't'},
		{"crypto", required_argument, NULL, 'c'},
		{"mutual", no_argument, NULL, 'm'},
		{"log-level", required_argument, NULL, 'l'},
		{0, 0, 0, 0}
	};

	char *attester_type = "";
	char *verifier_type = "";
	char *tls_type = "";
	char *crypto_type = "";
	bool mutual = false;
	enclave_tls_log_level_t log_level = ENCLAVE_TLS_LOG_LEVEL_DEFAULT;
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
		case 'm':
			mutual = true;
			break;
		case 'l':
			if (!strcasecmp(optarg, "debug"))
				log_level = ENCLAVE_TLS_LOG_LEVEL_DEBUG;
			else if (!strcasecmp(optarg, "info"))
				log_level = ENCLAVE_TLS_LOG_LEVEL_INFO;
			else if (!strcasecmp(optarg, "warn"))
				log_level = ENCLAVE_TLS_LOG_LEVEL_WARN;
			else if (!strcasecmp(optarg, "error"))
				log_level = ENCLAVE_TLS_LOG_LEVEL_ERROR;
			else if (!strcasecmp(optarg, "fatal"))
				log_level = ENCLAVE_TLS_LOG_LEVEL_FATAL;
			else if (!strcasecmp(optarg, "off"))
				log_level = ENCLAVE_TLS_LOG_LEVEL_NONE;
			break;
		case -1:
			break;
		default:
			exit(1);
		}
	} while (opt != -1);

	/* Create a socket that uses an internet IPv4 address,
	 * Sets the socket to be stream based (TCP),
	 * 0 means choose the default protocol.
	 */

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("failed to call socket()\n");
		return -1;
	}

	struct sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(DEFAULT_PORT);

	/* Get the server IPv4 address from the command line call */
	const char *srvaddr = "127.0.0.1";
	if (inet_pton(AF_INET, srvaddr, &s_addr.sin_addr) != 1) {
		fprintf(stderr, "invalid server address\n");
		return -1;
	}

	/* Connect to the server */
	if (connect(sockfd, (struct sockaddr *) &s_addr, sizeof(s_addr)) == -1) {
		perror("failed to call connect()\n");
		return -1;
	}

	return enclave_tls_echo(sockfd, log_level,
				attester_type, verifier_type, tls_type,
				crypto_type, mutual);
}
