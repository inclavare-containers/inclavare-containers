/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <rats-tls/api.h>
#include <rats-tls/log.h>

#define DEFAULT_PORT 1234
#define DEFAULT_IP   "127.0.0.1"

// clang-format off
#ifdef OCCLUM
#include <sgx_report.h>
#elif defined(SGX)
#include <sgx_urts.h>
#include <sgx_quote.h>
#include "sgx_stub_u.h"

#define ENCLAVE_FILENAME "sgx_stub_enclave.signed.so"
// clang-format on

rats_tls_log_level_t global_log_level = RATS_TLS_LOG_LEVEL_DEFAULT;

static sgx_enclave_id_t load_enclave(bool debug_enclave)
{
	sgx_launch_token_t t;

	memset(t, 0, sizeof(t));

	sgx_enclave_id_t eid;
	int updated = 0;
	int ret = sgx_create_enclave(ENCLAVE_FILENAME, debug_enclave, &t, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		RTLS_ERR("Failed to load enclave %d\n", ret);
		return 0;
	}

	RTLS_INFO("Success to load enclave with enclave id %ld\n", eid);

	return eid;
}

int rats_tls_client_startup(rats_tls_log_level_t log_level, char *attester_type,
			    char *verifier_type, char *tls_type, char *crypto_type, bool mutual,
			    bool debug_enclave, char *ip, int port)
{
	uint32_t s_ip = inet_addr(ip);
	uint16_t s_port = htons((uint16_t)port);

	sgx_enclave_id_t enclave_id = load_enclave(debug_enclave);
	if (enclave_id == 0) {
		RTLS_ERR("Failed to load sgx stub enclave\n");
		return -1;
	}

	unsigned long flags = 0;
	if (mutual)
		flags |= RATS_TLS_CONF_FLAGS_MUTUAL;

	int ret = 0;
	int sgx_status = ecall_rtls_client_startup((sgx_enclave_id_t)enclave_id, &ret,
						   (sgx_enclave_id_t)enclave_id, log_level,
						   attester_type, verifier_type, tls_type,
						   crypto_type, flags, s_ip, s_port);
	if (sgx_status != SGX_SUCCESS || ret)
		RTLS_ERR("failed to startup client: sgx status %#x return %#x\n", sgx_status, ret);

	return ret;
}
#endif

#ifndef SGX
int rats_tls_client_startup(rats_tls_log_level_t log_level, char *attester_type,
			    char *verifier_type, char *tls_type, char *crypto_type, bool mutual,
			    bool debug_enclave, char *ip, int port)
{
	rats_tls_conf_t conf;

	memset(&conf, 0, sizeof(conf));
	conf.log_level = log_level;
	strcpy(conf.attester_type, attester_type);
	strcpy(conf.verifier_type, verifier_type);
	strcpy(conf.tls_type, tls_type);
	strcpy(conf.crypto_type, crypto_type);
	conf.cert_algo = RATS_TLS_CERT_ALGO_DEFAULT;
	if (mutual)
		conf.flags |= RATS_TLS_CONF_FLAGS_MUTUAL;

	/* Create a socket that uses an internet IPv4 address,
	 * Sets the socket to be stream based (TCP),
	 * 0 means choose the default protocol.
	 */
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		RTLS_ERR("failed to call socket()\n");
		return -1;
	}

	struct sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(port);

	/* Get the server IPv4 address from the command line call */
	if (inet_pton(AF_INET, ip, &s_addr.sin_addr) != 1) {
		RTLS_ERR("invalid server address\n");
		return -1;
	}

	/* Connect to the server */
	if (connect(sockfd, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1) {
		RTLS_ERR("failed to call connect()\n");
		return -1;
	}

	rats_tls_handle handle;
	rats_tls_err_t ret = rats_tls_init(&conf, &handle);
	if (ret != RATS_TLS_ERR_NONE) {
		RTLS_ERR("Failed to initialize rats tls %#x\n", ret);
		return -1;
	}

	ret = rats_tls_set_verification_callback(&handle, NULL);
	if (ret != RATS_TLS_ERR_NONE) {
		RTLS_ERR("Failed to set verification callback %#x\n", ret);
		return -1;
	}

	ret = rats_tls_negotiate(handle, sockfd);
	if (ret != RATS_TLS_ERR_NONE) {
		RTLS_ERR("Failed to negotiate %#x\n", ret);
		goto err;
	}

	const char *msg = "Hello and welcome to RATS-TLS!\n";
	size_t len = strlen(msg);
	ret = rats_tls_transmit(handle, (void *)msg, &len);
	if (ret != RATS_TLS_ERR_NONE || len != strlen(msg)) {
		RTLS_ERR("Failed to transmit %#x\n", ret);
		goto err;
	}

	char buf[256];
	len = sizeof(buf);
	ret = rats_tls_receive(handle, buf, &len);
	if (ret != RATS_TLS_ERR_NONE) {
		RTLS_ERR("Failed to receive %#x\n", ret);
		goto err;
	}

	if (len >= sizeof(buf))
		len = sizeof(buf) - 1;
	buf[len] = '\0';

	#ifdef OCCLUM
	/* Server running in SGX Enclave will send mrenclave, mrsigner and hello message to client */
	if (len >= 2 * sizeof(sgx_measurement_t)) {
		RTLS_INFO("Server's SGX identity:\n");
		RTLS_INFO("  . MRENCLAVE = ");
		for (int i = 0; i < 32; ++i)
			printf("%02x", (uint8_t)buf[i]);
		printf("\n");
		RTLS_INFO("  . MRSIGNER  = ");
		for (int i = 32; i < 64; ++i)
			printf("%02x", (uint8_t)buf[i]);
		printf("\n");

		memcpy(buf, buf + 2 * sizeof(sgx_measurement_t),
		       len - 2 * sizeof(sgx_measurement_t));
		buf[len - 2 * sizeof(sgx_measurement_t)] = '\0';

		RTLS_INFO("Server:\n%s\n", buf);
	} else
	#endif
	{
		/* Server not running in SGX Enlcave will only send hello message to client */
		printf("Server: %s\n", buf);
	}

	/* Sanity check whether the response is expected */
	if (strcmp(msg, buf)) {
		RTLS_ERR("Invalid response retrieved from rats-tls server\n");
		goto err;
	}

	ret = rats_tls_cleanup(handle);
	if (ret != RATS_TLS_ERR_NONE)
		RTLS_ERR("Failed to cleanup %#x\n", ret);

	return ret;

err:
	/* Ignore the error code of cleanup in order to return the prepositional error */
	rats_tls_cleanup(handle);

	return -1;
}
#endif

int main(int argc, char **argv)
{
#ifdef SGX
	printf("    - Welcome to RATS-TLS sample client program for Intel SGX\n");
#elif defined(OCCLUM)
	printf("    - Welcome to RATS-TLS sample client program for Occlum\n");
#else
	printf("    - Welcome to RATS-TLS sample client program\n");
#endif

	char *const short_options = "a:v:t:c:ml:i:p:D:h";
	// clang-format off
	struct option long_options[] = {
		{ "attester", required_argument, NULL, 'a' },
		{ "verifier", required_argument, NULL, 'v' },
		{ "tls", required_argument, NULL, 't' },
		{ "crypto", required_argument, NULL, 'c' },
		{ "mutual", no_argument, NULL, 'm' },
		{ "log-level", required_argument, NULL, 'l' },
		{ "ip", required_argument, NULL, 'i' },
		{ "port", required_argument, NULL, 'p' },
		{ "debug-enclave", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	// clang-format on

	char *attester_type = "";
	char *verifier_type = "";
	char *tls_type = "";
	char *crypto_type = "";
	bool mutual = false;
	rats_tls_log_level_t log_level = RATS_TLS_LOG_LEVEL_INFO;
	char *srv_ip = DEFAULT_IP;
	int port = DEFAULT_PORT;
	bool debug_enclave = false;
	int opt;

	do {
		opt = getopt_long(argc, argv, short_options, long_options, NULL);
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
				log_level = RATS_TLS_LOG_LEVEL_DEBUG;
			else if (!strcasecmp(optarg, "info"))
				log_level = RATS_TLS_LOG_LEVEL_INFO;
			else if (!strcasecmp(optarg, "warn"))
				log_level = RATS_TLS_LOG_LEVEL_WARN;
			else if (!strcasecmp(optarg, "error"))
				log_level = RATS_TLS_LOG_LEVEL_ERROR;
			else if (!strcasecmp(optarg, "fatal"))
				log_level = RATS_TLS_LOG_LEVEL_FATAL;
			else if (!strcasecmp(optarg, "off"))
				log_level = RATS_TLS_LOG_LEVEL_NONE;
			break;
		case 'i':
			srv_ip = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'D':
			debug_enclave = true;
			break;
		case -1:
			break;
		case 'h':
			puts("    Usage:\n\n"
			     "        rats-tls-client <options> [arguments]\n\n"
			     "    Options:\n\n"
			     "        --attester/-a value   set the type of quote attester\n"
			     "        --verifier/-v value   set the type of quote verifier\n"
			     "        --tls/-t value        set the type of tls wrapper\n"
			     "        --crypto/-c value     set the type of crypto wrapper\n"
			     "        --mutual/-m           set to enable mutual attestation\n"
			     "        --log-level/-l        set the log level\n"
			     "        --ip/-i               set the listening ip address\n"
			     "        --port/-p             set the listening tcp port\n"
			     "        --debug-enclave/-D    set to enable enclave debugging\n"
			     "        --help/-h             show the usage\n");
			exit(1);
		default:
			exit(1);
		}
	} while (opt != -1);

	global_log_level = log_level;

	return rats_tls_client_startup(log_level, attester_type, verifier_type, tls_type,
				       crypto_type, mutual, debug_enclave, srv_ip, port);
}
