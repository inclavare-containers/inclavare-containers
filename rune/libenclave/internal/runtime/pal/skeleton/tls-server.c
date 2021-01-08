#include <netinet/in.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include "tls-server.h"
#include "sgx_urts.h"

#define ENCLAVE_FILENAME "Wolfssl_Enclave.signed.so"
#define DEFAULT_ADDRESS "/run/rune/ra-tls.sock"

extern int ra_tls_server_startup(sgx_enclave_id_t id, int sockfd);

int ra_tls_server(void)
{
	printf("    - Welcome to tls server\n");

	int updated = 0;
	sgx_enclave_id_t eid;
	sgx_launch_token_t t;
	memset(t, 0, sizeof(t));

	int ret = sgx_create_enclave(ENCLAVE_FILENAME, 1, &t, &updated, &eid,
				     NULL);
	if (ret != SGX_SUCCESS) {
		fprintf(stderr, "Failed to create Enclave: error %d\n", ret);
		return -1;
	}

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

	if (ra_tls_server_startup(eid, connd) == -1) {
		perror("Failed to start up the server.");
		goto err;
	}

	return 0;

err:
	close(sockfd);
	return -1;
}
