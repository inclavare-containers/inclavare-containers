/* Code to create an RA-TLS certificate with wolfSSL. */

#define _GNU_SOURCE // for memmem()
#define __USE_GNU

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef RATLS_ECDSA
#include <sgx_uae_service.h>
#include <sgx_trts.h>
#include <sgx_report.h>
#include <sgx_error.h>
#include <sgx_quote_3.h>
#endif

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

#ifdef RATLS_ECDSA
uint32_t enclave_create_report(const sgx_target_info_t* p_qe3_target, sgx_report_data_t *report_data, sgx_report_t* p_report)
{
	// Generate the report for the app_enclave
        sgx_status_t  sgx_error = sgx_create_report(p_qe3_target, report_data, p_report);

	return sgx_error;
}

/**
 * Generate RA-TLS certificate containing ECDSA-based attestation evidence.
 *
 * @param der_crt Caller must allocate memory for certificate.
 * @param der_crt_len On entry contains the size of der_crt buffer. On return holds actual size of certificate in bytes.
 */
static
void ecdsa_generate_x509
(
    RsaKey* key,
    uint8_t* der_crt,     /* out */
    int* der_crt_len, /* in/out */
    const ecdsa_attestation_evidence_t* evidence
)
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

    memcpy(crt.quote, evidence->quote, evidence->quote_len);
    crt.quoteSz = evidence->quote_len;

    RNG    rng;
    wc_InitRng(&rng);

    int certSz = wc_MakeSelfCert(&crt, der_crt, *der_crt_len, key, &rng);
    assert(certSz > 0);
    *der_crt_len = certSz;
}

static void
ecdsa_wolfssl_create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len
)
{
	/* Generate key. */
	RsaKey genKey;
	RNG    rng;
	int    ret;
	sgx_target_info_t qe_target_info;
	sgx_report_t app_report;

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

	/* Generate certificate */
	sgx_report_data_t report_data = {0, };
	sha256_rsa_pubkey(report_data.d, &genKey);
	ecdsa_attestation_evidence_t evidence;

	ocall_ratls_get_target_info(&qe_target_info);
	enclave_create_report(&qe_target_info, &report_data, &app_report);
	ocall_collect_attestation_evidence(&app_report, &evidence);

	ecdsa_generate_x509(&genKey, der_cert, der_cert_len, &evidence);
}

/**
 * @param der_key_len On the way in, this is the max size for the der_key parameter. On the way out, this is the actual size for der_key.
 * @param der_cert_len On the way in, this is the max size for the der_cert parameter. On the way out, this is the actual size for der_cert.
 */
void ecdsa_create_key_and_x509
(
    uint8_t* der_key,  /* out */
    int* der_key_len,  /* in/out */
    uint8_t* der_cert, /* out */
    int* der_cert_len /* in/out */
)
{
	ecdsa_wolfssl_create_key_and_x509(der_key, der_key_len,
			der_cert, der_cert_len);
}
#endif

#ifndef RATLS_ECDSA
#ifndef LA_REPORT
/**
 * Caller must allocate memory for certificate.
 *
 * @param der_crt_len On entry contains the size of der_crt buffer. On return holds actual size of certificate in bytes.
 */
static
void generate_x509
(
    RsaKey* key,
    uint8_t* der_crt,     /* out */
    int* der_crt_len, /* in/out */
    const attestation_verification_report_t* attn_report
)
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

    memcpy(crt.iasAttestationReport, attn_report->ias_report,
           attn_report->ias_report_len);
    crt.iasAttestationReportSz = attn_report->ias_report_len;

    memcpy(crt.iasSigCACert, attn_report->ias_sign_ca_cert,
           attn_report->ias_sign_ca_cert_len);
    crt.iasSigCACertSz = attn_report->ias_sign_ca_cert_len;

    memcpy(crt.iasSigCert, attn_report->ias_sign_cert,
           attn_report->ias_sign_cert_len);
    crt.iasSigCertSz = attn_report->ias_sign_cert_len;

    memcpy(crt.iasSig, attn_report->ias_report_signature,
           attn_report->ias_report_signature_len);
    crt.iasSigSz = attn_report->ias_report_signature_len;

    RNG    rng;
    wc_InitRng(&rng);
    
    int certSz = wc_MakeSelfCert(&crt, der_crt, *der_crt_len, key, &rng);
    assert(certSz > 0);
    *der_crt_len = certSz;
}

static void
wolfssl_create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len,
    const struct ra_tls_options* opts
)
{
    /* Generate key. */
    RsaKey genKey;
    RNG    rng;
    int    ret;

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

    /* Generate certificate */
    sgx_report_data_t report_data = {0, };
    sha256_rsa_pubkey(report_data.d, &genKey);
    attestation_verification_report_t attestation_report;

    do_remote_attestation(&report_data, opts, &attestation_report);

    generate_x509(&genKey, der_cert, der_cert_len,
                  &attestation_report);
}

/**
 * @param der_key_len On the way in, this is the max size for the der_key parameter. On the way out, this is the actual size for der_key.
 * @param der_cert_len On the way in, this is the max size for the der_cert parameter. On the way out, this is the actual size for der_cert.
 */
void create_key_and_x509
(
    uint8_t* der_key,  /* out */
    int* der_key_len,  /* in/out */
    uint8_t* der_cert, /* out */
    int* der_cert_len, /* in/out */
    const struct ra_tls_options* opts /* in */
)
{
    wolfssl_create_key_and_x509(der_key, der_key_len,
                                der_cert, der_cert_len,
                                opts);
}

void create_key_and_x509_pem
(
    uint8_t* pem_key,  /* out */
    int* pem_key_len,  /* in/out */
    uint8_t* pem_cert, /* out */
    int* pem_cert_len, /* in/out */
    const struct ra_tls_options* opts
)
{
    unsigned char der_key[16 * 1024] = {0, };
    int der_key_len = sizeof(der_key);
    unsigned char der_cert[16 * 1024] = {0, };
    int der_cert_len = sizeof(der_cert_len);
    int len;

    wolfssl_create_key_and_x509(der_key, &der_key_len,
                                der_cert, &der_cert_len,
                                opts);

    len = wc_DerToPem(der_key, der_key_len, pem_key, *pem_key_len, PRIVATEKEY_TYPE);
    assert(len > 0);
    *pem_key_len = len;

    len = wc_DerToPem(der_cert, der_cert_len, pem_cert, *pem_cert_len, CERT_TYPE);
    assert(len > 0);
    *pem_cert_len = len;
}
#endif
#endif

#ifdef WOLFSSL_SGX
time_t XTIME(time_t* tloc) {
    time_t x = 1512498557; /* Dec 5, 2017, 10:29 PDT */
    if (tloc) *tloc = x;
    return x;
}

time_t mktime(struct tm* tm) {
    (void) tm;
    assert(0);
    return (time_t) 0;
}
#endif
