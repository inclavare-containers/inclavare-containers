/* *INDENT-OFF* */
#ifndef _WOLFCRYPT_PRIVATE_H
#define _WOLFCRYPT_PRIVATE_H
/* *INDENT-ON* */

#include <enclave-tls/compilation.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/signature.h>

typedef struct {
	RsaKey key;
	unsigned int privkey_len;
	uint8_t privkey_buf[2048];
} wolfcrypt_secured_t;

typedef struct {
	wolfcrypt_secured_t __secured *secured;
} wolfcrypt_ctx_t;

extern const int rsa_pub_3072_raw_der_len;

/* *INDENT-OFF* */
#endif /* _WOLFCRYPT_PRIVATE_H */
/* *INDENT-ON* */
