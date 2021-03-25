/* *INDENT-OFF* */
#ifndef _WOLFSSL_SGX_H
#define _WOLFSSL_SGX_H
/* *INDENT-ON* */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "sgx_stub_u.h"

typedef struct {
	WOLFSSL_CTX *ws;
	WOLFSSL *ssl;
} wolfssl_sgx_ctx_t;

/* *INDENT-OFF* */
#endif /* _WOLFSSL_SGX_H */
/* *INDENT-ON* */
