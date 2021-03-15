#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include <assert.h>

#include "wolfssl_private.h"

/* *INDENT-OFF* */
tls_wrapper_err_t wolfssl_gen_cert(tls_wrapper_ctx_t *ctx,
				   const tls_wrapper_cert_info_t *cert_info)
{
	ETLS_DEBUG("tls_wrapper_wolfssl gen_cert is called\n");

	Cert crt;
	wc_InitCert(&crt);

	cert_subject_t *subject = &cert_info->subject;
	strncpy(crt.subject.org, subject->organization,
		sizeof(crt.subject.org) - 1);
	crt.subject.org[sizeof(crt.subject.org) - 1] = '\0';
	strncpy(crt.subject.unit, subject->organization_unit,
		sizeof(crt.subject.unit) - 1);
	crt.subject.unit[sizeof(crt.subject.unit) - 1] = '\0';
	strncpy(crt.subject.commonName, subject->common_name,
		sizeof(crt.subject.commonName) - 1);
	crt.subject.commonName[sizeof(crt.subject.commonName) - 1] = '\0';

	/* FIXME: add the handle of different quote types */
	if (!strcmp(cert_info->evidence.type, "sgx-epid")) {
		attestation_verification_report_t *epid = &cert_info->evidence.epid;

		assert(sizeof(crt.iasAttestationReport) >= epid->ias_report_len);
		memcpy(crt.iasAttestationReport, epid->ias_report, epid->ias_report_len);
		crt.iasAttestationReportSz = epid->ias_report_len;

		assert(sizeof(crt.iasSigCACert) >= epid->ias_sign_ca_cert_len);
		memcpy(crt.iasSigCACert, epid->ias_sign_ca_cert, epid->ias_sign_ca_cert_len);
		crt.iasSigCACertSz = epid->ias_sign_ca_cert_len;

		assert(sizeof(crt.iasSigCert) >= epid->ias_sign_cert_len);
		memcpy(crt.iasSigCert, epid->ias_sign_cert, epid->ias_sign_cert_len);
		crt.iasSigCertSz = epid->ias_sign_cert_len;

		assert(sizeof(crt.iasSig) >= epid->ias_report_signature_len);
		memcpy(crt.iasSig, epid->ias_report_signature, epid->ias_report_signature_len);
		crt.iasSigSz = epid->ias_report_signature_len;
	} else if (!strcmp(cert_info->evidence.type, "sgx-ecdsa")) {
		/* Empty Implement */
	} else if (!strcmp(cert_info->evidence.type, "sgx-la")) {
		/* Empty Implement */
	}

	RNG rng;
	wc_InitRng(&rng);

	tls_wrapper_err_t err = TLS_WRAPPER_ERR_NONE;

	wolfssl_ctx_t *ws_ctx = (wolfssl_ctx_t *)ctx->tls_private;

	ws_ctx->cert_len = wc_MakeSelfCert(&crt, ws_ctx->cert_buf,
					   sizeof(ws_ctx->cert_buf),
					   &(ws_ctx->key), &rng);
	if (ws_ctx->cert_len <= 0) {
		ETLS_ERR("ERROR: cert len %d is error\n", ws_ctx->cert_len);
		err = -TLS_WRAPPER_ERR_CERT;
	}

	return err;
}
/* *INDENT-ON* */
