/* Code to create an LA-TLS certificate with wolfSSL. */

#define _GNU_SOURCE // for memmem()
#define __USE_GNU

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <sgx_utils.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "ra.h"
#include "ra_tls_t.h"
#include "wolfssl-ra.h"
#include "ra-attester.h"
#include "ra-attester_private.h"
#include "ra_private.h"

/**
 * Generate LA-TLS certificate containing local report information.
 *
 * @param der_crt Caller must allocate memory for certificate.
 * @param der_crt_len On entry contains the size of der_crt buffer. On return holds actual size of certificate in bytes.
 */
static void la_generate_x509(RsaKey* key, uint8_t* der_crt,
		int* der_crt_len, const sgx_report_t* report)
{
    Cert crt;
    wc_InitCert(&crt);

    strncpy(crt.subject.country, "US", CTC_NAME_SIZE);
    strncpy(crt.subject.state, "OR", CTC_NAME_SIZE);
    strncpy(crt.subject.locality, "Hillsboro", CTC_NAME_SIZE);
    strncpy(crt.subject.org, "Intel Inc.", CTC_NAME_SIZE);
    strncpy(crt.subject.unit, "Intel Labs", CTC_NAME_SIZE);
    strncpy(crt.subject.commonName, "SGX rocks!", CTC_NAME_SIZE);
    strncpy(crt.subject.email, "webmaster@intel.com", CTC_NAME_SIZE);

    memcpy(crt.lareport, report, sizeof(sgx_report_t));
    crt.lareportSz = sizeof(sgx_report_t);

    RNG rng;
    wc_InitRng(&rng);

    int certSz = wc_MakeSelfCert(&crt, der_crt, *der_crt_len, key, &rng);
    assert(certSz > 0);
    *der_crt_len = certSz;
}

static void la_wolfssl_create_key_and_x509(uint8_t* der_key, int* der_key_len,
		uint8_t* der_cert, int* der_cert_len)
{
	RsaKey genKey;
	RNG rng;
	int ret;
	sgx_report_t report;
	sgx_target_info_t target_info;

	wc_InitRng(&rng);
	wc_InitRsaKey(&genKey, 0);
	ret = wc_MakeRsaKey(&genKey, 3072, 65537, &rng);
	assert(ret == 0);

	uint8_t der[4096];
	int  derSz = wc_RsaKeyToDer(&genKey, der, sizeof(der));
	assert(derSz >= 0);
	assert(derSz <= (int) *der_key_len);

	*der_key_len = derSz;
	memcpy(der_key, der, derSz);

	sgx_report_data_t report_data = {0, };
	sha256_rsa_pubkey(report_data.d, &genKey);

	sgx_self_target(&target_info);
	sgx_create_report(&target_info, &report_data, &report);
	la_generate_x509(&genKey, der_cert, der_cert_len, &report);
}

/**
 * @param der_key_len On the way in, this is the max size for the der_key parameter. On the way out, this is the actual size for der_key.
 * @param der_cert_len On the way in, this is the max size for the der_cert parameter. On the way out, this is the actual size for der_cert.
 */
void la_create_key_and_x509(uint8_t* der_key, int* der_key_len,
		uint8_t* der_cert, int* der_cert_len)
{
	la_wolfssl_create_key_and_x509(der_key, der_key_len,
			der_cert, der_cert_len);
}

int enc_la_sgx_verify_report(sgx_report_t* report)
{
	sgx_report_t report_t;
	memcpy(&report_t, report, sizeof(sgx_report_t));
	sgx_status_t status = sgx_verify_report(&report_t);

	return status;
}
