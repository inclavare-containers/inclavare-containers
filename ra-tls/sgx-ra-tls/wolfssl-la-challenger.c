/**
 * wolfSSL-based implementation of the LA-TLS challenger API
 * (cf. ra-challenger.h).
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <sgx_urts.h>

extern sgx_enclave_id_t geid;

void la_get_report_from_cert(const uint8_t* der_crt, uint32_t der_crt_len,
		sgx_report_t* report)
{
    DecodedCert crt;
    int ret;

    InitDecodedCert(&crt, (byte*) der_crt, der_crt_len, NULL);
    InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
    ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
    assert(ret == 0);
    la_get_report_from_extension(crt.extensions, crt.extensionsSz, report);

    FreeDecodedCert(&crt);
}

int la_verify_sgx_cert_extensions(uint8_t* der_crt, uint32_t der_crt_len)
{
	sgx_report_t report;
	int retval;

	la_get_report_from_cert(der_crt, der_crt_len, &report);
	enc_la_sgx_verify_report(geid, &retval, &report);
	if (retval == 0)
	{
		printf("Verify local report successfully!\n");
		return 0;
	} else {
		printf("Verify local report failure!\n");
		return -1;
	}
}
