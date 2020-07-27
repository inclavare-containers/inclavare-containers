/* Code to create an RA-TLS certificate with wolfSSL. */

#define _GNU_SOURCE // for memmem()

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sgx_uae_service.h>

#ifdef RATLS_ECDSA
#include <curl/curl.h>

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
#include "wolfssl-ra.h"
#include "ra-attester.h"
#include "ra-attester_private.h"
#ifdef RATLS_ECDSA
#include "ecdsa-ra-attester.h"
#include "ecdsa-sample-data/real/sample_data.h"
#include "ecdsa-attestation-collateral.h"
#include "curl_helper.h"

static const int FMSPC_SIZE_BYTES = 6;

#endif
#include "ra_private.h"

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

#ifdef RATLS_ECDSA
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

    memcpy(crt.pckCrt, evidence->pck_crt, evidence->pck_crt_len);
    crt.pckCrtSz = evidence->pck_crt_len;

    memcpy(crt.pckSignChain, evidence->pck_sign_chain,
           evidence->pck_sign_chain_len);
    crt.pckSignChainSz = evidence->pck_sign_chain_len;

    memcpy(crt.tcbInfo, evidence->tcb_info,
           evidence->tcb_info_len);
    crt.tcbInfoSz = evidence->tcb_info_len;

    memcpy(crt.tcbSignChain, evidence->tcb_sign_chain,
           evidence->tcb_sign_chain_len);
    crt.tcbSignChainSz = evidence->tcb_sign_chain_len;

    memcpy(crt.qeIdentity, evidence->qe_identity,
           evidence->qe_identity_len);
    crt.qeIdentitySz = evidence->qe_identity_len;

    memcpy(crt.rootCaCrl, evidence->root_ca_crl,
           evidence->root_ca_crl_len);
    crt.rootCaCrlSz = evidence->root_ca_crl_len;

    memcpy(crt.pckCrl, evidence->pck_crl,
           evidence->pck_crl_len);
    crt.pckCrlSz = evidence->pck_crl_len;
    
    RNG    rng;
    wc_InitRng(&rng);
    
    int certSz = wc_MakeSelfCert(&crt, der_crt, *der_crt_len, key, &rng);
    assert(certSz > 0);
    *der_crt_len = certSz;
}
#endif

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

    // generate_x509(&genKey, der_cert, der_cert_len,
       //           &attestation_report);
}

#ifdef RATLS_ECDSA
static void binary_to_base16
(
    const uint8_t* binary,
    uint32_t binary_len,
    char* base16,
    uint32_t base16_len
)
{
    /* + 1 for terminating null byte. */
    assert(base16_len >= binary_len * 2 + 1);
    
    for (uint32_t i = 0; i < binary_len; ++i) {
        sprintf(&base16[i * 2], "%02X", binary[i]);
    }
}

static
void ecdsa_get_quote_from_quote_service
(
    const sgx_report_data_t* report_data,
    uint8_t* quote,
    uint32_t* quote_len
)
{
#ifndef SGX_SIMULATION
    uint32_t quote_size = 0;
    sgx_target_info_t qe_target_info = {0, };
    int sockfd = connect_to_quote_service();
    get_target_info_from_quote_service(sockfd, &qe_target_info, &quote_size);
    assert(quote_size <= *quote_len);
    
    sgx_report_t report;
    create_report(&qe_target_info, report_data, &report);
    get_quote_from_quote_service(sockfd, &report, quote, quote_size);
    *quote_len = quote_size;
    
    close(sockfd);
#else
    (void) report_data;
    
    assert(ecdsa_sample_data_quote_ppid_rsa3072_dat_len <= *quote_len);
    memcpy(quote, ecdsa_sample_data_quote_ppid_rsa3072_dat, ecdsa_sample_data_quote_ppid_rsa3072_dat_len);
    *quote_len = ecdsa_sample_data_quote_ppid_rsa3072_dat_len;
#endif
}

/* static void print_byte_array(FILE* f, uint8_t* data, int size) { */
/*     for (int i = 0; i < size; ++i) { */
/*         fprintf(f, "%02X", data[i]); */
/*     } */
/* } */

/**
 * Pulls PCK certificate's signing chain information out of HTTP
 * response header. Also url-decodes it.
 */
static
void parse_response_header_get_pck_cert
(
    CURL* curl,
    const char* headers,
    size_t headers_len,
    char* pck_cert_chain,
    uint32_t* pck_cert_chain_len
)
{
    const char header_tag[] = "SGX-PCK-Certificate-Issuer-Chain: ";
    char* header_begin = memmem((const char*) headers,
                             headers_len,
                             header_tag,
                             strlen(header_tag));
    if (header_begin == NULL) {
        fprintf(stderr, "HTTP headers: %.*s\n", (int) headers_len, headers);
    }
    assert(header_begin != NULL);
    header_begin += strlen(header_tag);
    char* header_end = memmem(header_begin,
                           headers_len - (header_begin - headers),
                           "\r\n",
                           strlen("\r\n"));
    assert(header_end);

    int unescaped_len;
    char* unescaped = curl_easy_unescape(curl, header_begin, header_end - header_begin, &unescaped_len);
    assert(unescaped);
    assert(unescaped_len <= (int) *pck_cert_chain_len);
    memcpy(pck_cert_chain, unescaped, unescaped_len);
    *pck_cert_chain_len = unescaped_len;
    curl_free(unescaped);
}

/**
 * Today, this grabs the PCK certificate from Intel's backend service
 * and stores it in evidence.pck_crt.
 *
 * Tomorrow, this may grab the PCK certificate from somewhere else,
 * e.g., some local PCK certificate caching service.
 */
static
void obtain_pck_cert
(
    ecdsa_attestation_evidence_t* evidence,
    const struct ecdsa_ra_tls_options* opts,
    sgx_ql_ppid_rsa3072_encrypted_cert_info_t* cert_data
)
{
    char encrypted_ppid[786 + 1];
    binary_to_base16(cert_data->enc_ppid, sizeof(cert_data->enc_ppid),
                     encrypted_ppid, sizeof(encrypted_ppid));

    char pceid[4 + 1];
    binary_to_base16((uint8_t*)&cert_data->pce_info.pce_id,
                     sizeof(cert_data->pce_info.pce_id),
                     pceid, sizeof(pceid));

    char pcesvn[4 + 1];
    binary_to_base16((uint8_t*)&cert_data->pce_info.pce_isv_svn,
                     sizeof(cert_data->pce_info.pce_isv_svn),
                     pcesvn, sizeof(pcesvn));

    char cpusvn[32 + 1];
    binary_to_base16((uint8_t*)&cert_data->cpu_svn,
                     sizeof(cert_data->cpu_svn),
                     cpusvn, sizeof(cpusvn));

#ifdef DEBUG
    printf("%s:%s: PPID=%s\nPCE ID= %s\nPCE SVN= %s\nCPU SVN= %s\n",
           __FILE__, __FUNCTION__, encrypted_ppid, pceid, pcesvn, cpusvn);
#endif
    
    char url[2048];
    const char base_url[] = "https://api.trustedservices.intel.com/sgx/certification/v1/pckcert";
    snprintf(url, sizeof(url), "%s?encrypted_ppid=%s&cpusvn=%s&pcesvn=%s&pceid=%s",
             base_url, encrypted_ppid, cpusvn, pcesvn, pceid);
    /* printf("URL= %s\n", url); */
    /* printf("subscription_key= %.32s\n", opts->subscription_key); */
    
    CURL* curl = curl_easy_init();
    assert(curl != NULL);
    struct buffer_and_size header = {(char*) malloc(1), 0};
    struct buffer_and_size body   = {(char*) malloc(1), 0};
    
    char buf[128];
    int rc = snprintf(buf, sizeof(buf), "Ocp-Apim-Subscription-Key: %.32s",
                      opts->subscription_key);
    assert(rc < (int) sizeof(buf));
                 
    struct curl_slist* request_headers = NULL;
    request_headers = curl_slist_append(request_headers, buf);
    
    http_get(curl, url, &header, &body, request_headers, NULL);

    evidence->pck_sign_chain_len = sizeof(evidence->pck_sign_chain);
    parse_response_header_get_pck_cert(curl, header.data, header.len,
                                       (char*) evidence->pck_sign_chain,
                                       &evidence->pck_sign_chain_len);

    assert(sizeof(evidence->pck_crt) >= body.len);
    memcpy(evidence->pck_crt, body.data, body.len);
    evidence->pck_crt_len = body.len;
    
    curl_easy_cleanup(curl);
    free(header.data);
    free(body.data);
    curl_slist_free_all(request_headers);
}

/**
 * Pulls TCB info's signing chain from HTTP response header. Also url-decodes it.
 */
static
void parse_response_header_tcb_info_cert_chain
(
    CURL* curl,
    const char* headers,
    size_t headers_len,
    char* cert_chain,
    uint32_t* cert_chain_len
)
{
    const char header_tag[] = "SGX-TCB-Info-Issuer-Chain: ";
    char* header_begin = memmem((const char*) headers,
                             headers_len,
                             header_tag,
                             strlen(header_tag));
    assert(header_begin != NULL);
    header_begin += strlen(header_tag);
    char* header_end = memmem(header_begin,
                           headers_len - (header_begin - headers),
                           "\r\n",
                           strlen("\r\n"));
    assert(header_end);

    int unescaped_len;
    char* unescaped = curl_easy_unescape(curl, header_begin, header_end - header_begin, &unescaped_len);
    assert(unescaped);
    assert((int) *cert_chain_len >= unescaped_len);
    memcpy(cert_chain, unescaped, unescaped_len);
    *cert_chain_len = unescaped_len;
}

static void init(void) __attribute__((constructor));
static void init(void) {
    /* Apparently this function is not thread-safe
       (cf. https://curl.haxx.se/libcurl/c/curl_global_init.html
       ). Calling it from within the library initializer hopefully
       solves this. */
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

static void deinit(void) __attribute__((destructor));
static void deinit(void) {
    curl_global_cleanup();
}

/**
 * Today, obtains the TCB information from Intel's backend service and
 * stores it in evidence.tcb_info along with the signing chain in
 * evidence.tcb_sign_chain.
 *
 * Tomorrow, this may obtain the TCB info from some local caching
 * service, from an on-disk file, etc.
 */
static
void obtain_tcb_info
(
    char fmspc[6],
    ecdsa_attestation_evidence_t* evidence
)
{
    /* Need 2 * 6 bytes when encoded into
       hexadecimal. +1 byte for terminating NUL. */
    char fmspc_base16[FMSPC_SIZE_BYTES * 2 + 1];
    binary_to_base16((unsigned char*) fmspc, FMSPC_SIZE_BYTES, fmspc_base16,
                     sizeof(fmspc_base16));
    
    char url[256];
    int rc = snprintf(url, sizeof(url),
                      "https://api.trustedservices.intel.com/sgx/certification/v1/tcb?fmspc=%s",
                      fmspc_base16);
    assert(rc < (int) sizeof(url));

    CURL *curl = curl_easy_init();
    struct buffer_and_size header = {(char*) malloc(1), 0};
    struct buffer_and_size body   = {(char*) malloc(1), 0};
    http_get(curl, url, &header, &body, NULL, NULL);

    evidence->tcb_sign_chain_len = sizeof(evidence->tcb_sign_chain);
    parse_response_header_tcb_info_cert_chain(curl, header.data, header.len,
                                              (char*) evidence->tcb_sign_chain,
                                              &evidence->tcb_sign_chain_len);

    assert(sizeof(evidence->tcb_info) >= body.len);
    evidence->tcb_info_len = sizeof(evidence->tcb_info);
    memcpy(evidence->tcb_info, body.data, body.len);
    evidence->tcb_info_len = body.len;

    curl_easy_cleanup(curl);
    free(header.data);
    free(body.data);
}

/**
 * The FMSPC field is contained in the PCK certificate. Find the FMSPC
 * OID and extract it.
 */
static
void extract_fmspc_from_pck_cert
(
    char fmspc[6],
    ecdsa_attestation_evidence_t* evidence
)
{
    assert(NULL != evidence->pck_crt);
    assert(evidence->pck_crt_len > 0);

    uint8_t pck_crt_der[2048];
    uint32_t pck_crt_der_len = sizeof(pck_crt_der);
    int bytes = wolfSSL_CertPemToDer(evidence->pck_crt, evidence->pck_crt_len,
                                     pck_crt_der, pck_crt_der_len, CERT_TYPE);
    assert(bytes > 0);
    pck_crt_der_len = (uint32_t) bytes;
    
    DecodedCert crt;

    InitDecodedCert(&crt, (byte*) pck_crt_der, pck_crt_der_len, NULL);
    InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
    int ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
    assert(ret == 0);

    /* fmspc_oid[0] = 0x06 ... ASN.1 type (0x06 is OID)
       fmspc_oid[1] = 0x0a ... length of OID in bytes, i.e., 10 bytes.
       fmspc_oid[2 .. ] ... the OID 1.2.840.113741.1.13.1.4 */
    const uint8_t fmspc_oid[] = { 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86,
                                  0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04 };
    uint8_t* p = memmem(crt.extensions, crt.extensionsSz,
                            fmspc_oid, sizeof(fmspc_oid));
    assert(NULL != p);
    p += sizeof(fmspc_oid);
    /* p[0] ... ASN.1 type, i.e., octet string (0x04) */
    assert(p[0] == 0x04);
    /* p[1] ... length in bytes, i.e., 6 bytes (0x06) */
    assert(p[1] == FMSPC_SIZE_BYTES);
    p += 2;
    FreeDecodedCert(&crt);

    memcpy(fmspc, p, FMSPC_SIZE_BYTES);
}

/**
 * Given a quote, gets corresponding PCK certificate.
 *
 * First, inspects the quote for all the values required to obtain the
 * PCK certificate. Second, request PCK certificate from backend
 * service.
 */
static
void ecdsa_get_pck_cert
(
    ecdsa_attestation_evidence_t* evidence,
    const struct ecdsa_ra_tls_options* opts
)
{
    sgx_quote3_t* q = (sgx_quote3_t*) evidence->quote;
    assert(evidence->quote_len == sizeof(sgx_quote3_t) + q->signature_data_len);
    sgx_quote_header_t quote_header = q->header;
    assert(quote_header.version == 3);
    assert(quote_header.att_key_type == 2);

    sgx_ql_ecdsa_sig_data_t* sig_data =
        (sgx_ql_ecdsa_sig_data_t*) (q->signature_data);
    sgx_ql_auth_data_t* auth_data =
        (sgx_ql_auth_data_t*) (sig_data->auth_certification_data);
    sgx_ql_certification_data_t* cert_data_generic =
        (sgx_ql_certification_data_t*) (sig_data->auth_certification_data +
                                        sizeof(*auth_data) + auth_data->size);
    
    assert(cert_data_generic->cert_key_type == PPID_RSA3072_ENCRYPTED);

    /* printf("ppid enc type= %d\n", cert_data_generic->cert_key_type); */

    /* if (cert_data_generic->cert_key_type == PPID_CLEARTEXT) { */
    /*     sgx_ql_ppid_cleartext_cert_info_t* cert_info = */
    /*         (sgx_ql_ppid_cleartext_cert_info_t*) (cert_data_generic->certification_data); */
    /*     char ppid_base16[16*2]; */
    /*     binary_to_base16(cert_info->ppid, sizeof(cert_info->ppid), */
    /*                      ppid_base16, sizeof(ppid_base16)); */
    /*     printf("PPID= %.32s\n", ppid_base16); */
    /*     assert(0); */
    /* } */
    
    assert(cert_data_generic->size == sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t));
    sgx_ql_ppid_rsa3072_encrypted_cert_info_t* cert_data =
        (sgx_ql_ppid_rsa3072_encrypted_cert_info_t*) (cert_data_generic->certification_data);

    obtain_pck_cert(evidence, opts, cert_data);
}

/**
 * Obtains quote, PCK certificate, TCB information, Quoting Enclave
 * identity and certificate revocation lists.
 */
static
void collect_attestation_evidence
(
    const sgx_report_data_t* report_data,
    const struct ecdsa_ra_tls_options* opts,
    ecdsa_attestation_evidence_t* evidence
)
{
    evidence->quote_len = sizeof(evidence->quote);
    ecdsa_get_quote_from_quote_service(report_data, evidence->quote, &evidence->quote_len);
    
    ecdsa_get_pck_cert(evidence, opts);
    
    char fmspc[6];
    extract_fmspc_from_pck_cert(fmspc, evidence);
    obtain_tcb_info(fmspc, evidence);

    /* For now, these values are hard-coded in the executable. In the
       future, they may be fetched dynamically. */
    memcpy(evidence->qe_identity, qe_identity_json, qe_identity_json_len);
    evidence->qe_identity_len = qe_identity_json_len;
    memcpy(evidence->root_ca_crl, root_ca_crl_pem, root_ca_crl_pem_len);
    evidence->root_ca_crl_len = root_ca_crl_pem_len;
    memcpy(evidence->pck_crl, pck_crl_pem, pck_crl_pem_len);
    evidence->pck_crl_len = pck_crl_pem_len;
}

static void
ecdsa_wolfssl_create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len,
    const struct ecdsa_ra_tls_options* opts
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
    ecdsa_attestation_evidence_t evidence;

    collect_attestation_evidence(&report_data, opts, &evidence);

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
    int* der_cert_len, /* in/out */
    const struct ecdsa_ra_tls_options* opts /* in */
)
{
    ecdsa_wolfssl_create_key_and_x509(der_key, der_key_len,
                                      der_cert, der_cert_len,
                                      opts);
}
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
    const struct ra_tls_options* opts, /* in */
    void* targetinfo, void* data, void* report
)
{
    wolfssl_create_key_and_x509(der_key, der_key_len,
                                der_cert, der_cert_len,
                                opts);
}

static void create_key_111
(
	uint8_t* der_key,  /* out */
	int* der_key_len,  /* in/out */
	uint8_t* der_cert, /* out */
	int* der_cert_len, /* in/out */
	const struct ra_tls_options* opts, /* in */
	void* targetinfo, void* data, void* report
)
{
	wolfssl_create_key_and_x509(der_key, der_key_len,
			            der_cert, der_cert_len,
				    opts);
}

static void
wolfssl_create_key
(
	uint8_t* der_key,
	int* der_key_len,
 	uint8_t* der_cert,
	int* der_cert_len,
 	const struct ra_tls_options* opts,
	void* targetinfo, void* data, void* report
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
