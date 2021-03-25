#include <enclave-tls/tls_wrapper.h>
#include <enclave-tls/log.h>
#include "wolfssl_enclave_u.h"

tls_wrapper_err_t ecall_wolfssl_pre_init(void)
{
	return TLS_WRAPPER_ERR_NONE;
}

tls_wrapper_err_t ecall_wolfssl_init(tls_wrapper_ctx_t *ctx)
{
	tls_wrapper_err_t retval;
	sgx_enclave_id_t g_eid = ctx->tls_private->config.eid;

	enc_wolfssl_init(g_eid, &retval, ctx);
	if (retval != TLS_WRAPPER_ERR_NONE)
		printf("ecall_wolfssl_init error\n");

	return TLS_WRAPPER_ERR_NONE;
}

tls_wrapper_err_t ecall_wolfssl_use_privkey(tls_wrapper_ctx_t* ctx,
					void *__secured privkey_buf,
					size_t privkey_len)
{
	tls_wrapper_err_t retval;
	sgx_enclave_id_t g_eid = ctx->tls_private->config.eid;

	enc_wolfssl_use_privkey(g_eid, &retval, ctx, privkey_buf, privkey_len);
	if (retval != TLS_WRAPPER_ERR_NONE)
		printf("ecall_wolfssl_use_privkey error\n");

	return TLS_WRAPPER_ERR_NONE;
}

tls_wrapper_err_t ecall_wolfssl_use_cert(tls_wrapper_ctx_t* ctx,
			enclave_tls_cert_info_t *cert_info)
{
	tls_wrapper_err_t retval;
	sgx_enclave_id_t g_eid = ctx->tls_private->config.eid;

	enc_wolfssl_use_cert(g_eid, &retval, ctx, cert_info);
	if (retval != TLS_WRAPPER_ERR_NONE)
		printf("ecall_wolfssl_use_cert error\n");

	return TLS_WRAPPER_ERR_NONE;
}

tls_wrapper_err_t ecall_wolfssl_negotiate(tls_wrapper_ctx_t *ctx, int fd)
{
	tls_wrapper_err_t retval;
	sgx_enclave_id_t g_eid = ctx->tls_private->config.eid;

	enc_wolfssl_negotiate(g_eid, &retval, ctx, fd);
	if (retval != TLS_WRAPPER_ERR_NONE)
		printf("ecall_wolfssl_negotiate error\n");

	return TLS_WRAPPER_ERR_NONE;
}

tls_wrapper_err_t ecall_wolfssl_transmit(tls_wrapper_ctx_t* ctx, void * buf,
		size_t *buf_size)
{
	tls_wrapper_err_t retval;
	sgx_enclave_id_t g_eid = ctx->tls_private->config.eid;

	enc_wolfssl_transmit(g_eid, &retval, ctx, buf, buf_size);
	if (retval != TLS_WRAPPER_ERR_NONE)
		printf("ecall_wolfssl_transimit error\n");

	return TLS_WRAPPER_ERR_NONE;
}

tls_wrapper_err_t ecall_wolfssl_receive(tls_wrapper_ctx_t * ctx, void *buf, size_t *buf_size)
{
	tls_wrapper_err_t retval;
	sgx_enclave_id_t g_eid = ctx->tls_private->config.eid;

	enc_wolfssl_receive(g_eid, &retval, ctx, buf, buf_size);
	if (retval != TLS_WRAPPER_ERR_NONE)
		printf("ecall_wolfssl_receive error\n");

	return TLS_WRAPPER_ERR_NONE;
}

tls_wrapper_err_t ecall_wolfssl_cleanup(tls_wrapper_ctx_t* ctx)
{
	tls_wrapper_err_t retval;
	sgx_enclave_id_t g_eid = ctx->tls_private->config.eid;

	enc_wolfssl_cleanup(g_eid, &retval, ctx);
	if (retval != TLS_WRAPPER_ERR_NONE)
		printf("ecall_wolfssl_cleanup error\n");

	return TLS_WRAPPER_ERR_NONE;
}

static tls_wrapper_opts_t enc_wolfssl_opts = {
	.version = TLS_WRAPPER_API_VERSION_DEFAULT,
	.type = "wolfssl_sgx",
	.priority = 4,
	.pre_init = ecall_wolfssl_pre_init,
	.init = ecall_wolfssl_init,
	.use_privkey = ecall_wolfssl_use_privkey,
	.use_cert = ecall_wolfssl_use_cert,
	.negotiate = ecall_wolfssl_negotiate,
	.transmit = ecall_wolfssl_transmit,
	.receive = ecall_wolfssl_receive,
	.cleanup = ecall_wolfssl_cleanup,
};

/* *INDENT-OFF* */
void __attribute__((constructor))
libtls_wrapper_wolfssl_sgx_init(void)
{
	ETLS_DEBUG("The constructor of libtls_wrapper_wolfssl_sgx.so is called\n");

	tls_wrapper_err_t err = tls_wrapper_register(&enc_wolfssl_opts);
	if (err != TLS_WRAPPER_ERR_NONE) {
		ETLS_ERR("ERROR: failed to register tls wrapper instance \"WOLFSSL SGX\"\n");
	}
}
/* *INDENT-ON* */
