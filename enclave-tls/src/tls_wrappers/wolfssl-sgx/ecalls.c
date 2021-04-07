#include <assert.h>
#include "sgx_stub_t.h"
#include "../wolfssl/pre_init.c"
#include "../wolfssl/init.c"
#include "../wolfssl/use_privkey.c"
#include "../wolfssl/use_cert.c"
#include "../wolfssl/negotiate.c"
#include "../wolfssl/transmit.c"
#include "../wolfssl/receive.c"
#include "../wolfssl/cleanup.c"
#include "../wolfssl/oid.c"

tls_wrapper_err_t ecall_wolfssl_pre_init(void)
{
	return wolfssl_pre_init();
}

tls_wrapper_err_t ecall_wolfssl_init(tls_wrapper_ctx_t *ctx)
{
	return wolfssl_init(ctx);
}

tls_wrapper_err_t ecall_wolfssl_use_privkey(tls_wrapper_ctx_t *ctx,
					    void *privkey_buf,
					    size_t privkey_len)
{
	return wolfssl_use_privkey(ctx, privkey_buf, privkey_len);
}

tls_wrapper_err_t ecall_wolfssl_use_cert(tls_wrapper_ctx_t *ctx,
					 enclave_tls_cert_info_t *cert_info)
{
	return wolfssl_use_cert(ctx, cert_info);
}

tls_wrapper_err_t ecall_wolfssl_negotiate(tls_wrapper_ctx_t *ctx, int fd)
{
	return wolfssl_negotiate(ctx, fd);
}

tls_wrapper_err_t ecall_wolfssl_transmit(tls_wrapper_ctx_t *ctx, void *buf,
				 size_t *buf_size)
{
	return wolfssl_transmit(ctx, buf, buf_size);
}

tls_wrapper_err_t ecall_wolfssl_receive(tls_wrapper_ctx_t *ctx, void *buf,
				size_t *buf_size)
{
	return wolfssl_receive(ctx, buf, buf_size);
}

tls_wrapper_err_t ecall_wolfssl_cleanup(tls_wrapper_ctx_t *ctx)
{
	return wolfssl_cleanup(ctx);
}

size_t recv(int sockfd, void *buf, size_t len, int flags)
{
	size_t ret;
	int sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);
	assert(sgxStatus == SGX_SUCCESS);

	return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
	size_t ret;
	int sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);
	assert(sgxStatus == SGX_SUCCESS);

	return ret;
}
