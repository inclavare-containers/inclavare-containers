#include <stdlib.h>
#ifndef SGX
#include <dlfcn.h>
#endif
#include <string.h>
#include "enclave-tls/log.h"
#include "err.h"

#ifdef SGX
extern void libcrypto_wrapper_nullcrypto_init(void);
extern void libcrypto_wrapper_wolfcrypt_init(void);
extern void libenclave_quote_nullquote_init(void);
extern void libenclave_quote_sgx_ecdsa_init(void);
extern void libenclave_quote_sgx_ecdsa_qve_init(void);
extern void libenclave_quote_sgx_la_init(void);
extern void libtls_wrapper_nulltls_init(void);
extern void libtls_wrapper_wolfssl_init(void);
#endif

enclave_tls_err_t etls_instance_libinit(const char *name,
                                        const char *realpath,
                                        void **handle
                                       )
{
#ifdef SGX
	if (!strcmp(name, "nullcrypto"))
		libcrypto_wrapper_nullcrypto_init();
	else if (!strcmp(name, "wolfcrypt"))
		libcrypto_wrapper_wolfcrypt_init();
	else if (!strcmp(name, "nullquote"))
		libenclave_quote_nullquote_init();
	else if (!strcmp(name, "sgx_ecdsa"))
		libenclave_quote_sgx_ecdsa_init();
	else if (!strcmp(name, "sgx_ecdsa_qve"))
		libenclave_quote_sgx_ecdsa_qve_init();
	else if (!strcmp(name, "sgx_la"))
		libenclave_quote_sgx_la_init();
	else if (!strcmp(name, "nulltls"))
		libtls_wrapper_nulltls_init();
	else if (!strcmp(name, "wolfssl"))
		libtls_wrapper_wolfssl_init();
	else
		return ENCLAVE_TLS_ERR_NO_NAME;
#else
	*handle = dlopen(realpath, RTLD_LAZY);
	if (*handle == NULL) {
		ETLS_ERR("failed on dlopen(): %s\n", dlerror());
		return -ENCLAVE_TLS_ERR_DLOPEN;
	}
#endif

	return ENCLAVE_TLS_ERR_NONE;
}
