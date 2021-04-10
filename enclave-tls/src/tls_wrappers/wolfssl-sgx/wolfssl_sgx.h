#ifndef _WOLFSSL_SGX_H
#define _WOLFSSL_SGX_H

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "sgx_stub_u.h"

typedef struct {
	WOLFSSL_CTX *ws;
	WOLFSSL *ssl;
} wolfssl_sgx_ctx_t;

#endif
