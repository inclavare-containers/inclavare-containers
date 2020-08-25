#ifdef __cplusplus
extern "C" {
#endif
    
void obtain_attestation_verification_report(
    const sgx_quote_t* quote,
    const uint32_t quote_size,
    const struct ra_tls_options* opts,
    attestation_verification_report_t* attn_report
);
    
#ifdef __cplusplus
}
#endif
