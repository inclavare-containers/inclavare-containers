/**
 * wolfSSL-based implementation of the RA-TLS challenger API
 * (cf. ra-challenger.h).
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#ifdef RATLS_ECDSA
#include <sgx_quote_3.h>
#include <sgx_ql_quote.h>
#include <sgx_dcap_quoteverify.h>
#endif

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/signature.h>

#include <sgx_urts.h>

#include "ra.h"
#include "wolfssl-ra.h"
#include "ra-challenger.h"
#include "ra-challenger_private.h"

extern unsigned char ias_sign_ca_cert_der[];
extern unsigned int ias_sign_ca_cert_der_len;
extern int la_verify_sgx_cert_extensions(uint8_t* der_crt, uint32_t der_crt_len);

void get_quote_from_cert
(
    const uint8_t* der_crt,
    uint32_t der_crt_len,
    sgx_quote_t* q
)
{
    DecodedCert crt;
    int ret;

    InitDecodedCert(&crt, (byte*) der_crt, der_crt_len, NULL);
    InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
    ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
    assert(ret == 0);
    
    get_quote_from_extension(crt.extensions, crt.extensionsSz, q);

    FreeDecodedCert(&crt);
}

#ifdef RATLS_ECDSA
void ecdsa_get_quote_from_dcap_cert
(
    const uint8_t* der_crt,
    uint32_t der_crt_len,
    sgx_quote3_t* q
)
{
    DecodedCert crt;
    int ret;

    InitDecodedCert(&crt, (byte*) der_crt, der_crt_len, NULL);
    InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
    ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
    assert(ret == 0);
    ecdsa_get_quote_from_extension(crt.extensions, crt.extensionsSz, q);

    FreeDecodedCert(&crt);

}
#endif

void get_quote_from_report
(
    const uint8_t* report /* in */,
    const int report_len  /* in */,
    sgx_quote_t* quote
)
{
    // Move report into \0 terminated buffer such that we can work
    // with str* functions.
    char buf[report_len + 1];
    memcpy(buf, report, report_len);
    buf[report_len] = '\0';

    const char* json_string = "\"isvEnclaveQuoteBody\":\"";
    char* p_begin = strstr(buf, json_string);
    assert(p_begin != NULL);
    p_begin += strlen(json_string);
    const char* p_end = strchr(p_begin, '"');
    assert(p_end != NULL);

    const int quote_base64_len = p_end - p_begin;
    uint8_t* quote_bin = malloc(quote_base64_len);
    if (!quote_bin) {
        fprintf(stderr, "ERROR: failed to malloc quote bin buffer.\n");
        return;
    }
    uint32_t quote_bin_len = quote_base64_len;

    Base64_Decode((const byte*) p_begin, quote_base64_len,
                  quote_bin, &quote_bin_len);
    
    assert(quote_bin_len <= sizeof(sgx_quote_t));
    memset(quote, 0, sizeof(sgx_quote_t));
    memcpy(quote, quote_bin, quote_bin_len);
    free(quote_bin);
}

static
int verify_report_data_against_server_cert
(
    DecodedCert* crt,
    sgx_quote_t* quote
)
{
    /* crt->publicKey seems to be the DER encoded public key. The
       OpenSSL DER formatted version of the public key obtained with
       openssl rsa -in ./server-key.pem -pubout -outform DER -out
       server-pubkey.der has an additional 24 bytes
       prefix/header. d->pubKeySize is 270 and the server-pubkey.der
       file has 294 bytes. That's to be expected according to [1] */
    /* [1] https://crypto.stackexchange.com/questions/14491/why-is-a-2048-bit-public-rsa-key-represented-by-540-hexadecimal-characters-in  */
    
    /* 2017-12-06, Thomas Knauth, A hard-coded offset into the
       DER-encoded public key only works for specific key sizes. The
       24 byte offset is specific to 2048 bit RSA keys. For example, a
       1024 bit RSA key only has an offset of 22.
 */
    RsaKey rsaKey;
    unsigned int idx = 0;
    int ret;
    
    wc_InitRsaKey(&rsaKey, NULL);
    ret = wc_RsaPublicKeyDecode(crt->publicKey, &idx, &rsaKey, crt->pubKeySize);
    assert(ret == 0);
    
    byte shaSum[SHA256_DIGEST_SIZE] = {0, };
    sha256_rsa_pubkey(shaSum, &rsaKey);
    wc_FreeRsaKey(&rsaKey);

#ifdef DEBUG
    fprintf(stderr, "SHA256 of server's public key:\n");
    for (int i=0; i < SHA256_DIGEST_SIZE; ++i) fprintf(stderr, "%02x", shaSum[i]);
    fprintf(stderr, "\n");

    fprintf(stderr, "Quote's report data:\n");
    for (int i=0; i < SGX_REPORT_DATA_SIZE; ++i) fprintf(stderr, "%02x", quote->report_body.report_data.d[i]);
    fprintf(stderr, "\n");
#endif
    
    assert(SHA256_DIGEST_SIZE <= SGX_REPORT_DATA_SIZE);
    ret = memcmp(quote->report_body.report_data.d, shaSum, SHA256_DIGEST_SIZE);
    assert(ret == 0);

    return ret;
}

static
int verify_ias_report_signature
(
    attestation_verification_report_t* attn_report
)
{
    DecodedCert crt;
    int ret;

    uint8_t der[4096];
    int der_len;
    der_len = wolfSSL_CertPemToDer(attn_report->ias_sign_cert, attn_report->ias_sign_cert_len,
                                   der, sizeof(der),
                                   CERT_TYPE);
    assert(der_len > 0);
    
    InitDecodedCert(&crt, der, der_len, NULL);
    InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
    ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
    assert(ret == 0);

    RsaKey rsaKey;
    unsigned int idx = 0;
    
    ret = wc_InitRsaKey(&rsaKey, NULL);
    assert(ret == 0);
    ret = wc_RsaPublicKeyDecode(crt.publicKey, &idx, &rsaKey, crt.pubKeySize);
    assert(ret == 0);

    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256,
                             /* This is required such that signature
                                matches what OpenSSL produces. OpenSSL
                                embeds the hash in an ASN.1 structure
                                before signing it. */
                             WC_SIGNATURE_TYPE_RSA_W_ENC,
                             attn_report->ias_report, attn_report->ias_report_len,
                             attn_report->ias_report_signature, attn_report->ias_report_signature_len,
                             &rsaKey, sizeof(rsaKey));

    FreeDecodedCert(&crt);
    wc_FreeRsaKey(&rsaKey);

    return ret;
}

static
int verify_ias_certificate_chain(attestation_verification_report_t* attn_report) {
    WOLFSSL_CERT_MANAGER* cm;

    cm = wolfSSL_CertManagerNew();
    assert(cm != NULL);

    /* like load verify locations, 1 for success, < 0 for error */
    int ret = wolfSSL_CertManagerLoadCABuffer(cm, ias_sign_ca_cert_der,
                                              ias_sign_ca_cert_der_len,
                                              SSL_FILETYPE_ASN1);
    assert(ret == 1);
    
    ret = wolfSSL_CertManagerVerifyBuffer(cm, attn_report->ias_sign_cert,
                                          attn_report->ias_sign_cert_len,
                                          SSL_FILETYPE_PEM);
    assert(ret == SSL_SUCCESS);
    
    wolfSSL_CertManagerFree(cm);
    cm = NULL;
    
    return 0;
}

/**
 * Check if isvEnclaveQuoteStatus is "OK"
 * (cf. https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf,
 * pg. 24).
 *
 * @return 0 if verified successfully, 1 otherwise.
 */
static
int verify_enclave_quote_status
(
    const char* ias_report,
    int   ias_report_len
)
{
    // Move ias_report into \0 terminated buffer such that we can work
    // with str* functions.
    char buf[ias_report_len + 1];
    memcpy(buf, ias_report, ias_report_len);
    buf[ias_report_len] = '\0';
    
    const char* json_string = "\"isvEnclaveQuoteStatus\":\"";
    char* p_begin = strstr(buf, json_string);
    assert(p_begin != NULL);
    p_begin += strlen(json_string);

    const char* status_OK = "OK\"";
    if (0 == strncmp(p_begin, status_OK, strlen(status_OK))) return 0;
#ifdef SGX_GROUP_OUT_OF_DATE
    const char* status_outdated = "GROUP_OUT_OF_DATE\"";
    if (0 == strncmp(p_begin, status_outdated, strlen(status_outdated))) {
        printf("WARNING: isvEnclaveQuoteStatus is GROUP_OUT_OF_DATE\n");
        return 0;
    }
#endif
    return 1;
}

#ifdef RATLS_ECDSA
static
int ecdsa_verify_sgx_cert_extensions
(
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    int ret = 0;
    time_t current_time = 0;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;
    sgx_status_t sgx_ret = SGX_SUCCESS;
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    uint32_t collateral_expiration_status = 1;
    quote3_error_t verify_qveid_ret = SGX_QL_ERROR_UNEXPECTED;
    //specified defined for trusted veirification based on qve.
    //sgx_enclave_id_t eid = 0;
    //sgx_launch_token_t token = { 0 };
    //sgx_ql_qe_report_info_t qve_report_info;
    //unsigned char rand_nonce[16] = "59jslk201fgjmm;";
    //int updated = 0;

    //get quote from dcap cert extensions
    sgx_quote3_t* pquote = NULL;
    pquote = malloc(8192);
    if (!pquote) {
        fprintf(stderr, "ERROR: failed to malloc pquote buffer.\n");
        return -1;
    }
    ecdsa_get_quote_from_dcap_cert(der_crt, der_crt_len, pquote);
    uint32_t quote_size = 436 + pquote->signature_data_len;
    printf("quote size is %d;  quote signature_data_len is %d.\n", quote_size, pquote->signature_data_len);

    bool verify_by_qve = 0; //1 means trusted verify methond by QvE, 0 means verify by untructed QPL;
    if (verify_by_qve) { //In current stage, some machine is for pre-prouction and verifying by QvE is not supported;
        printf("verify by trusted model.\n");
        ret = 1;
    }
    else {
        //call DCAP quote verify library to get supplemental data size
        dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
        if (dcap_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t)) {
            printf("sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
            p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
	    if (!p_supplemental_data) {
		fprintf(stderr, "ERROR: failed to malloc p_supplemental_data buffer.\n");
		return -1;
	    }
        }
        else {
            fprintf(stderr, "ERROR: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x.\n", dcap_ret);
            supplemental_data_size = 0;
        }
        //set current time. This is only for sample purposes, in production mode a trusted time should be used.
        current_time = time(NULL);
        //call DCAP quote verify library for quote verification
        //here you can choose 'untrusted' quote verification by specifying parameter '&qve_report_info' as NULL
        dcap_ret = sgx_qv_verify_quote(
            pquote, quote_size,
            NULL,
            current_time,
            &collateral_expiration_status,
            &quote_verification_result,
            NULL,
            supplemental_data_size,
            p_supplemental_data);
        if (dcap_ret == SGX_QL_SUCCESS) {
            printf("App: sgx_qv_verify_quote successfully returned.\n");
        }
        else {
            fprintf(stderr, "ERROR: App: sgx_qv_verify_quote failed: 0x%04x\n", dcap_ret);
        }
        //check verification result
        switch (quote_verification_result)
        {
        case SGX_QL_QV_RESULT_OK:
            printf("App: Verification completed successfully.\n");
            ret = 0;
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            printf("Warning: App: Verification completed with Non-terminal result: %x\n", quote_verification_result);
            ret = 1;
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            fprintf(stderr, "ERROR: App: Verification completed with Terminal result: %x\n", quote_verification_result);
            ret = -1;
            break;
        }
        if (p_supplemental_data != NULL)
            free(p_supplemental_data);
        if (pquote != NULL)
            free(pquote);
    }
    return ret;
}
#else
static
int epid_verify_sgx_cert_extensions
(
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    attestation_verification_report_t attn_report;

    DecodedCert crt;
    int ret;

    InitDecodedCert(&crt, der_crt, der_crt_len, NULL);
    InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
    ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
    assert(ret == 0);

    extract_x509_extensions(crt.extensions, crt.extensionsSz, &attn_report);

    /* Base64 decode attestation report signature. */
    uint8_t sig_base64[sizeof(attn_report.ias_report_signature)];
    memcpy(sig_base64, attn_report.ias_report_signature, attn_report.ias_report_signature_len);
    int rc = Base64_Decode(sig_base64, attn_report.ias_report_signature_len,
                           attn_report.ias_report_signature, &attn_report.ias_report_signature_len);
    assert(0 == rc);

    ret = verify_ias_certificate_chain(&attn_report);
    assert(ret == 0);

    ret = verify_ias_report_signature(&attn_report);
    assert(ret == 0);

    ret = verify_enclave_quote_status((const char*) attn_report.ias_report,
                                      attn_report.ias_report_len);
    assert(ret == 0);

    sgx_quote_t quote = {0, };
    get_quote_from_report(attn_report.ias_report,
                          attn_report.ias_report_len,
                          &quote);
    ret = verify_report_data_against_server_cert(&crt, &quote);
    assert(ret == 0);

    FreeDecodedCert(&crt);

    return 0;
}
#endif

int verify_sgx_cert_extensions
(
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
#ifdef RATLS_ECDSA
    return ecdsa_verify_sgx_cert_extensions(der_crt, der_crt_len);
#elif defined(LA_REPORT)
    return la_verify_sgx_cert_extensions(der_crt, der_crt_len);
#else
    if (is_epid_ratls_cert(der_crt, der_crt_len)) {
        return epid_verify_sgx_cert_extensions(der_crt, der_crt_len);
    }
#endif

    assert(0);
    // Avoid compiler error: control reaches end of non-void function
    // [-Werror=return-type]
    return -1;
}
