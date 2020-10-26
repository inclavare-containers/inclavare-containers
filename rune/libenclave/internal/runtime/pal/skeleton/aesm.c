#include "aesm.h"
#include "aesm.pb-c.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int connect_aesm_service(void)
{
	int sock;
	struct sockaddr_un addr;

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("opening stream socket.");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, "/var/run/aesmd/aesm.socket",
		sizeof(addr.sun_path));

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("connecting stream socket.");
		close(sock);
		return -1;
	}

	return sock;
}

/* *INDENT-OFF* */
static int request_aesm_service(AesmServiceRequest *req,
				AesmServiceResponse **res)
{
	int aesm_socket = connect_aesm_service();
	if (aesm_socket < 0)
		return aesm_socket;

	uint32_t req_len =
		(uint32_t) aesm_service_request__get_packed_size(req);
	uint8_t *req_buf = alloca(req_len);
	aesm_service_request__pack(req, req_buf);

	if (write(aesm_socket, &req_len, sizeof(req_len)) < 0)
		goto err;
	if (write(aesm_socket, req_buf, req_len) < 0)
		goto err;

	uint32_t res_len;
	int size_read;
	if (read(aesm_socket, &res_len, sizeof(res_len)) < 0)
		goto err;

	uint8_t *res_buf = alloca(res_len);
	if ((size_read = read(aesm_socket, res_buf, res_len)) < 0)
		goto err;
	if (size_read != res_len) {
		fprintf(stderr,
			"aesm_service returned invalid response size (returned %d, expected %d).\n",
			size_read, res_len);
		goto err;
	}

	*res = aesm_service_response__unpack(NULL, res_len, res_buf);
	return *res == NULL ? -1 : 0;
err:
	close(aesm_socket);
	return -1;
}
/* *INDENT-ON* */

bool get_launch_token(struct sgx_sigstruct *sigstruct,
		      struct sgx_einittoken *token)
{
	AesmServiceRequest req = AESM_SERVICE_REQUEST__INIT;
	AesmServiceRequest__GetLaunchToken getreq =
		AESM_SERVICE_REQUEST__GET_LAUNCH_TOKEN__INIT;

	getreq.enclavehash.data = (uint8_t *) (sigstruct->body.mrenclave);
	getreq.enclavehash.len = sizeof(sigstruct->body.mrenclave);
	getreq.modulus.data = (uint8_t *) (sigstruct->modulus);
	getreq.modulus.len = sizeof(sigstruct->modulus);
	getreq.attributes.data = (uint8_t *) (&sigstruct->body.attributes);
	getreq.attributes.len =
		sizeof(sigstruct->body.attributes) +
		sizeof(sigstruct->body.xfrm);
	getreq.timeout = 10000;
	req.getlaunchtoken = &getreq;

	AesmServiceResponse *res = NULL;
	if (request_aesm_service(&req, &res) < 0)
		return false;
	if (!res->getlaunchtoken) {
		fprintf(stderr,
			"aesm_service returned wrong launch token message.\n");
		goto failed;
	}

	AesmServiceResponse__GetLaunchToken *r = res->getlaunchtoken;
	if (r->error != 0) {
		fprintf(stderr, "aesm_service returned error: %d.\n", r->error);
		goto failed;
	}
	if (r->token.len != sizeof(struct sgx_einittoken)) {
		fprintf(stderr, "aesm_service returned invaild token.\n");
		goto failed;
	}

	memcpy(token, r->token.data, sizeof(struct sgx_einittoken));
	return true;
failed:
	aesm_service_response__free_unpacked(res, NULL);
	return false;
}
