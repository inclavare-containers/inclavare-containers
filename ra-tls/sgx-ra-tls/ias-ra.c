#define _GNU_SOURCE // for memmem()

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#if defined(USE_OPENSSL)
#include <openssl/evp.h> // for base64 encode/decode
#elif defined(USE_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/coding.h>
#elif defined(USE_MBEDTLS)
#include <mbedtls/base64.h>
#else
#error Must use one of OpenSSL/wolfSSL/mbedtls
#endif

#include <stdint.h>

#include <sgx_report.h>

#include "ra.h"
#include "ra-attester.h"
#include "ias-ra.h"
#include "curl_helper.h"

static
size_t accumulate_function(void *ptr, size_t size, size_t nmemb, void *userdata) {
    struct buffer_and_size* s = (struct buffer_and_size*) userdata;
    s->data = (char*) realloc(s->data, s->len + size * nmemb);
    assert(s->data != NULL);
    memcpy(s->data + s->len, ptr, size * nmemb);
    s->len += size * nmemb;
    
    return size * nmemb;
}

void http_get
(
    CURL* curl,
    const char* url,
    struct buffer_and_size* header,
    struct buffer_and_size* body,
    struct curl_slist* request_headers,
    char* request_body
)
{
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
    
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, accumulate_function);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, accumulate_function);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, body);

    if (request_headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, request_headers);
    }
    if (request_body) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body);
    }

    CURLcode res = curl_easy_perform(curl);
    assert(res == CURLE_OK);
}

static const char pem_marker_begin[] = "-----BEGIN CERTIFICATE-----";
static const char pem_marker_end[] = "-----END CERTIFICATE-----";

static
void extract_certificates_from_response_header
(
    CURL* curl,
    const char* header,
    size_t header_len,
    attestation_verification_report_t* attn_report
)
{
    // Locate x-iasreport-signature HTTP header field in the response.
    const char response_header_name[] = "X-IASReport-Signing-Certificate: ";
    char *field_begin = memmem(header,
                               header_len,
                               response_header_name,
                               strlen(response_header_name));
    assert(field_begin != NULL);
    field_begin += strlen(response_header_name);
    const char http_line_break[] = "\r\n";
    char *field_end = memmem(field_begin,
                             header_len - (field_begin - header),
                             http_line_break,
                             strlen(http_line_break));
    size_t field_len = field_end - field_begin;

    // Remove urlencoding from x-iasreport-signing-certificate field.
    int unescaped_len = 0;
    char* unescaped = curl_easy_unescape(curl,
                                         field_begin,
                                         field_len,
                                         &unescaped_len);
    
    char* cert_begin = memmem(unescaped,
                              unescaped_len,
                              pem_marker_begin,
                              strlen(pem_marker_begin));
    assert(cert_begin != NULL);
    char* cert_end = memmem(unescaped, unescaped_len,
                            pem_marker_end, strlen(pem_marker_end));
    assert(cert_end != NULL);
    uint32_t cert_len = cert_end - cert_begin + strlen(pem_marker_end);

    assert(cert_len <= sizeof(attn_report->ias_sign_cert));
    memcpy(attn_report->ias_sign_cert, cert_begin, cert_len);
    attn_report->ias_sign_cert_len = cert_len;
    
    cert_begin = memmem(cert_end,
                        unescaped_len - (cert_end - unescaped),
                        pem_marker_begin,
                        strlen(pem_marker_begin));
    assert(cert_begin != NULL);
    cert_end = memmem(cert_begin,
                     unescaped_len - (cert_begin - unescaped),
                     pem_marker_end,
                     strlen(pem_marker_end));
    assert(cert_end != NULL);
    cert_len = cert_end - cert_begin + strlen(pem_marker_end);

    assert(cert_len <= sizeof(attn_report->ias_sign_ca_cert));
    memcpy((char*) attn_report->ias_sign_ca_cert, cert_begin, cert_len);
    attn_report->ias_sign_ca_cert_len = cert_len;

    curl_free(unescaped);
    unescaped = NULL;
}

/* The header has the certificates and report signature. */
void parse_response_header
(
    const char* header,
    size_t header_len,
    unsigned char* signature,
    const size_t signature_max_size,
    uint32_t* signature_size
)
{
    const char sig_tag[] = "X-IASReport-Signature: ";
    char* sig_begin = memmem((const char*) header,
                             header_len,
                             sig_tag,
                             strlen(sig_tag));
    assert(sig_begin != NULL);
    sig_begin += strlen(sig_tag);
    char* sig_end = memmem(sig_begin,
                           header_len - (sig_begin - header),
                           "\r\n",
                           strlen("\r\n"));
    assert(sig_end);

    assert((size_t) (sig_end - sig_begin) <= signature_max_size);
    memcpy(signature, sig_begin, sig_end - sig_begin);
    *signature_size = sig_end - sig_begin;
}

/**
 * @return Length of base64 encoded data including terminating NUL-byte.
 */
static void base64_encode
(
    uint8_t *in,
    uint32_t in_len,
    uint8_t* out,
    uint32_t* out_len /* in/out */
)
{
    // + 1 to account for the terminating \0.
    assert(*out_len >= (in_len + 3 - 1) / 3 * 4 + 1);
    bzero(out, *out_len);
    
#if defined(USE_OPENSSL)
        int ret = EVP_EncodeBlock(out, in, in_len);
        // + 1 since EVP_EncodeBlock() returns length excluding the terminating \0.
        assert((size_t) ret + 1 <= *out_len);
        *out_len = ret + 1;
#elif defined(USE_WOLFSSL)
        int ret = Base64_Encode_NoNl(in, in_len, out, out_len);
        assert(ret == 0);
        // No need append terminating \0 since we memset() the whole
        // buffer in the beginning.
        *out_len += 1;
#elif defined(USE_MBEDTLS)
        size_t olen;
        int ret = mbedtls_base64_encode(out, *out_len, &olen, in, in_len);
        assert(ret == 0);
        assert(olen <= UINT32_MAX);
        *out_len = (uint32_t) olen;
#endif
}

/** Turns a binary quote into an attestation verification report.

  Communicates with Intel Attestation Service via its HTTP REST interface.
*/
void obtain_attestation_verification_report
(
    const sgx_quote_t* quote,
    const uint32_t quote_size,
    const struct ra_tls_options* opts,
    attestation_verification_report_t* attn_report
)
{
    int ret;
  
    char url[512];
    ret = snprintf(url, sizeof(url), "https://%s/attestation/v3/report",
                   opts->ias_server);
    assert(ret < (int) sizeof(url));
    
    char buf[128];
    int rc = snprintf(buf, sizeof(buf), "Ocp-Apim-Subscription-Key: %.32s",
                      opts->subscription_key);
    assert(rc < (int) sizeof(buf));

    struct curl_slist *request_headers =
        curl_slist_append(NULL, "Content-Type: application/json");
    request_headers = curl_slist_append(request_headers, buf);
        
    const char json_template[] = "{\"isvEnclaveQuote\":\"%s\"}";
    unsigned char quote_base64[quote_size * 2];
    uint32_t quote_base64_len = sizeof(quote_base64);
    char json[quote_size * 2];

    base64_encode((uint8_t*) quote, quote_size,
                  quote_base64, &quote_base64_len);

    snprintf(json, sizeof(json), json_template, quote_base64);

    CURL *curl = curl_easy_init();
    assert(curl != NULL);
    struct buffer_and_size header = {(char*) malloc(1), 0};
    struct buffer_and_size body = {(char*) malloc(1), 0};
    http_get(curl, url, &header, &body, request_headers, json);
        
    parse_response_header(header.data, header.len,
                          attn_report->ias_report_signature,
                          sizeof(attn_report->ias_report_signature),
                          &attn_report->ias_report_signature_len);

    assert(sizeof(attn_report->ias_report) >= body.len);
    memcpy(attn_report->ias_report, body.data, body.len);
    attn_report->ias_report_len = body.len;

    extract_certificates_from_response_header(curl,
                                              header.data, header.len,
                                              attn_report);
    
    curl_easy_cleanup(curl);
    free(header.data);
    free(body.data);
    curl_slist_free_all(request_headers);
}
