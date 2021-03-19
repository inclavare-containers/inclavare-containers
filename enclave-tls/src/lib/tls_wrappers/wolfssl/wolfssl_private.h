/* *INDENT-OFF* */
#ifndef _WOLFSSL_PRIVATE_H
#define _WOLFSSL_PRIVATE_H
/* *INDENT-ON* */

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/signature.h>

typedef struct {
	WOLFSSL_CTX *ws;
	WOLFSSL *ssl;
} wolfssl_ctx_t;

extern const int rsa_pub_3072_raw_der_len;
extern const uint8_t ias_response_body_oid[];
extern const uint8_t ias_root_cert_oid[];
extern const uint8_t ias_leaf_cert_oid[];
extern const uint8_t ias_report_signature_oid[];

extern const uint8_t quote_oid[];
extern const uint8_t pck_crt_oid[];
extern const uint8_t pck_sign_chain_oid[];
extern const uint8_t tcb_info_oid[];
extern const uint8_t tcb_sign_chain_oid[];

extern const size_t ias_oid_len;

/* *INDENT-OFF* */
#endif /* _WOLFSSL_PRIVATE_H */
/* *INDENT-ON* */
