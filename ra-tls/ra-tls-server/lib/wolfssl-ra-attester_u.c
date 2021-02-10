#define _GNU_SOURCE // for memmem()
#define __USE_GNU
#define RATLS_ECDSA

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <curl/curl.h>

#include <sgx_uae_service.h>

//#ifdef RATLS_ECDSA
#include <curl/easy.h>
#include "sgx_urts.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_default_quote_provider.h"
#include "sgx_ql_lib_common.h"
#include "sgx_pce.h"
#include "sgx_error.h"
#include "sgx_quote_3.h"
#include "curl_helper.h"
//#endif

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
#include "ra_tls_u.h"
#ifdef RATLS_ECDSA
static const int FMSPC_SIZE_BYTES = 6;
#endif
#include "ra_private.h"

#define SGX_AESM_ADDR "SGX_AESM_ADDR"
typedef void CURL;
#define CURL_GLOBAL_SSL (1<<0)
#define CURL_GLOBAL_WIN32 (1<<1)
#define CURL_GLOBAL_ALL (CURL_GLOBAL_SSL|CURL_GLOBAL_WIN32)
#define CURL_GLOBAL_NOTHING 0
#define CURL_GLOBAL_DEFAULT CURL_GLOBAL_ALL
#define CURL_GLOBAL_ACK_EINTR (1<<2)
sgx_enclave_id_t geid = 0;

bool create_app_enclave_report(sgx_enclave_id_t eid, sgx_target_info_t qe_target_info, sgx_report_t *app_report)
{
        bool ret = true;
        uint32_t retval = 0;
        sgx_status_t sgx_status = SGX_SUCCESS;
        int launch_token_updated = 0;
        sgx_launch_token_t launch_token = { 0 };


        sgx_status = enclave_create_report(eid,
                &retval,
                &qe_target_info,
                app_report);
        if ((SGX_SUCCESS != sgx_status) || (0 != retval)) {
                printf("\nCall to get_app_enclave_report() failed\n");
                ret = false;
        }

        return ret;
}

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
void ecdsa_get_quote
(
    const sgx_report_data_t* report_data,
    ecdsa_attestation_evidence_t* evidence,
    uint8_t* quote,
    uint32_t* quote_len
)
{
    int ret = 0;
    quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    uint32_t quote_size = 0;
    uint8_t* p_quote_buffer = NULL;
    sgx_target_info_t qe_target_info;
    //sgx_report_t app_report;
    sgx_report_t report;
    sgx_quote3_t *p_quote;
    sgx_ql_auth_data_t *p_auth_data;
    sgx_ql_ecdsa_sig_data_t *p_sig_data;
    sgx_ql_certification_data_t *p_cert_data;
    bool is_out_of_proc = false;

    char *out_of_proc = "true";//getenv(SGX_AESM_ADDR);
    if(out_of_proc)
        is_out_of_proc = true;
#if !defined(_MSC_VER)
    // There 2 modes on Linux: one is in-proc mode, the QE3 and PCE are loaded within the user's process.
    // the other is out-of-proc mode, the QE3 and PCE are managed by a daemon. If you want to use in-proc
    // mode which is the default mode, you only need to install libsgx-dcap-ql. If you want to use the
    // out-of-proc mode, you need to install libsgx-quote-ex as well. This sample is built to demo both 2
    // modes, so you need to install libsgx-quote-ex to enable the out-of-proc mode.
    if(!is_out_of_proc)
    {
        // Following functions are valid in Linux in-proc mode only.
        printf("sgx_qe_set_enclave_load_policy is valid in in-proc mode only and it is optional: the default enclave load policy is persistent: \n");
        printf("set the enclave load policy as persistent:");
        qe3_ret = sgx_qe_set_enclave_load_policy(SGX_QL_PERSISTENT);
        if(SGX_QL_SUCCESS != qe3_ret) {
            printf("Error in set enclave load policy: 0x%04x\n", qe3_ret);
            ret = -1;
            goto CLEANUP;
        }
        printf("succeed!\n");

        // Try to load PCE and QE3 from Ubuntu-like OS system path
        if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so")) {

            // Try to load PCE and QE3 from RHEL-like OS system path
            if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib64/libsgx_pce.signed.so") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib64/libsgx_qe3.signed.so")) {
                printf("Error in set PCE/QE3 directory.\n");
                ret = -1;
                goto CLEANUP;
            }
        }

        qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1");
        if (SGX_QL_SUCCESS != qe3_ret) {
            qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib64/libdcap_quoteprov.so.1");
            if(SGX_QL_SUCCESS != qe3_ret) {
                // Ignore the error, because user may want to get cert type=3 quote
                printf("Warning: Cannot set QPL directory, you may get ECDSA quote with `Encrypted PPID` cert type.\n");
            }
        }
    }
#endif
printf("\nStep1: Call sgx_qe_get_target_info:");
    qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
                ret = -1;
        goto CLEANUP;
    }
    printf("succeed!");
    printf("\nStep2: Call create_app_report:");
    create_app_enclave_report(geid, qe_target_info, &report);
   /* if(true != sgx_create_report(qe_target_info, report_data, &report)) {
        printf("\nCall to create_app_report() failed\n");
        ret = -1;
        goto CLEANUP;
    }*/

    printf("succeed!");
    printf("\nStep3: Call sgx_qe_get_quote_size:");
    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }

    printf("succeed!");
    p_quote_buffer = (uint8_t*)malloc(quote_size);
    if (NULL == p_quote_buffer) {
        printf("Couldn't allocate quote_buffer\n");
        ret = -1;
        goto CLEANUP;
    }
    memset(p_quote_buffer, 0, quote_size);

    // Get the Quote
    printf("\nStep4: Call sgx_qe_get_quote:");
    qe3_ret = sgx_qe_get_quote(&report,
        quote_size,
        p_quote_buffer);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf( "Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
        ret = -1;
        goto CLEANUP;
    }
    printf("succeed!");

    p_quote = (sgx_quote3_t*)p_quote_buffer;
    p_sig_data = (sgx_ql_ecdsa_sig_data_t *)p_quote->signature_data;
    p_auth_data = (sgx_ql_auth_data_t*)p_sig_data->auth_certification_data;
    p_cert_data = (sgx_ql_certification_data_t *)((uint8_t *)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);
    
    memcpy(evidence->pck_crt, p_cert_data, 2048);
    evidence->pck_crt_len = 2048;    
    memcpy(evidence->pck_sign_chain, p_cert_data + 2048, 4096);
    evidence->pck_sign_chain_len = 4096;

    printf("cert_key_type = 0x%x\n", p_cert_data->cert_key_type);
    

    memcpy(quote, (uint8_t *)p_quote, sizeof(sgx_quote3_t));
    *quote_len = sizeof(sgx_quote3_t);

    if( !is_out_of_proc )
    {
        printf("sgx_qe_cleanup_by_policy is valid in in-proc mode only.\n");
        printf("\n Clean up the enclave load policy:");
        qe3_ret = sgx_qe_cleanup_by_policy();
        if(SGX_QL_SUCCESS != qe3_ret) {
            printf("Error in cleanup enclave load policy: 0x%04x\n", qe3_ret);
            ret = -1;
            goto CLEANUP;
        }
        printf("succeed!\n");
    }

CLEANUP:
    if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
    }
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
        printf("Error : HTTP headers: %.*s\n", (int) headers_len, headers);
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
void collect_attestation_evidence
(
    const sgx_report_data_t* report_data,
    const struct ecdsa_ra_tls_options* opts,
    ecdsa_attestation_evidence_t* evidence
)
{
    struct _sgx_ql_qve_collateral_t *p_quote_collateral = NULL;

    evidence->quote_len = sizeof(evidence->quote);
    ecdsa_get_quote(report_data, evidence, evidence->quote, &evidence->quote_len);
    
    
    /*memcpy(evidence->pck_crt, p_cert_data, 2048);
    evidence->pck_crt_len = 2048;
    memcpy(evidence->pck_sign_chain, p_cert_data + 2048, 4096);
    evidence->pck_sign_chain_len = 4096;*/

    ecdsa_get_pck_cert(evidence, opts);
    
    char fmspc[6];
    extract_fmspc_from_pck_cert(fmspc, evidence);
    //obtain_tcb_info(fmspc, evidence);

/*    if (fmspc == NULL || pck_ca == NULL || pp_quote_collateral == NULL || *pp_quote_collateral != NULL) {
	    return SGX_QL_ERROR_INVALID_PARAMETER;
    }
//    if (!sgx_dcap_load_qpl()) {
//	return SGX_QL_PLATFORM_LIB_UNAVAILABLE;		    
  //  }
*/
    sgx_ql_get_quote_verification_collateral(fmspc, sizeof(fmspc), "platform", &p_quote_collateral);

    memcpy(evidence->tcb_info, p_quote_collateral->tcb_info, p_quote_collateral->tcb_info_size);
    evidence->tcb_info_len = p_quote_collateral->tcb_info_size;
    memcpy(evidence->tcb_sign_chain, p_quote_collateral->tcb_info_issuer_chain, p_quote_collateral->tcb_info_issuer_chain_size);
    evidence->tcb_sign_chain_len = p_quote_collateral->tcb_info_issuer_chain_size;
    memcpy(evidence->qe_identity, p_quote_collateral->qe_identity, p_quote_collateral->qe_identity_size);
    evidence->qe_identity_len = p_quote_collateral->qe_identity_size;
    memcpy(evidence->root_ca_crl, p_quote_collateral->root_ca_crl, p_quote_collateral->root_ca_crl_size);
    evidence->root_ca_crl_len = p_quote_collateral->root_ca_crl_size;
    memcpy(evidence->pck_crl, p_quote_collateral->pck_crl, p_quote_collateral->pck_crl_size);
    evidence->pck_crl_len = p_quote_collateral->pck_crl_size;

}

