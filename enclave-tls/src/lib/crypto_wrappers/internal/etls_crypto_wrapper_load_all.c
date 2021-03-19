#include <string.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/crypto_wrapper.h"

static int crypto_wrapper_cmp(const void *a, const void *b)
{
	return (*(crypto_wrapper_ctx_t **)b)->opts->priority -
		(*(crypto_wrapper_ctx_t **)a)->opts->priority;
}

enclave_tls_err_t etls_crypto_wrapper_load_all(void)
{
	ETLS_DEBUG("called\n");

	DIR *dir = opendir(CRYPTO_WRAPPERS_PATH);
	if (!dir) {
		ETLS_ERR("failed to open %s", CRYPTO_WRAPPERS_PATH);
		return -ENCLAVE_TLS_ERR_UNKNOWN;
	}

	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;

	unsigned int total_num = 0;

	struct dirent *ptr;
	while ((ptr = readdir(dir))) {
		if (!strcmp(ptr->d_name, ".") ||
		    !strcmp(ptr->d_name, ".."))
			continue;

		if (ptr->d_type == DT_REG) {
			if ((err = etls_crypto_wrapper_load_single(ptr->d_name)) == ENCLAVE_TLS_ERR_NONE)
				++total_num;
		}
	}

	closedir(dir);

	if (!total_num) {
		ETLS_ERR("unavailable crypto wrapper instance under %s\n",
			 CRYPTO_WRAPPERS_PATH);
		return -ENCLAVE_TLS_ERR_LOAD_CRYPTO;
	}

	/* Sort all enclave_quote_ctx_t instances in the enclave_quotes_ctx, and the higher priority
	 * instance should be sorted in front of the enclave_quotes_ctx array.
	 */
	qsort(crypto_wrappers_ctx, crypto_wrappers_nums, sizeof(crypto_wrapper_ctx_t *),
	      crypto_wrapper_cmp);

	return ENCLAVE_TLS_ERR_NONE;
}