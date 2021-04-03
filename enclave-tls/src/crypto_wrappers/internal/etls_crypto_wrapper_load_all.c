#include <string.h>
#include <stdlib.h>
#include <dirent.h>
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

	DIR *dir = opendir(CRYPTO_WRAPPERS_DIR);
	if (!dir) {
		ETLS_ERR("failed to open %s", CRYPTO_WRAPPERS_DIR);
		return -ENCLAVE_TLS_ERR_UNKNOWN;
	}

	unsigned int total_loaded = 0;
	struct dirent *ptr;
	while ((ptr = readdir(dir))) {
		if (!strcmp(ptr->d_name, ".") ||
		    !strcmp(ptr->d_name, ".."))
			continue;

		if (ptr->d_type == DT_REG) {
			if (etls_crypto_wrapper_load_single(ptr->d_name) == ENCLAVE_TLS_ERR_NONE)
				++total_loaded;
		}
	}

	closedir(dir);

	if (!total_loaded) {
		ETLS_ERR("unavailable crypto wrapper instance under %s\n",
			 CRYPTO_WRAPPERS_DIR);
		return -ENCLAVE_TLS_ERR_LOAD_CRYPTO_WRAPPERS;
	}

	/* Sort all crypto_wrapper_ctx_t instances in the crypto_wrappers_ctx, and the higher priority
	 * instance should be sorted in front of the crypto_wrapper_ctx_t array.
	 */
	qsort(crypto_wrappers_ctx, crypto_wrappers_nums, sizeof(crypto_wrapper_ctx_t *),
	      crypto_wrapper_cmp);

	return ENCLAVE_TLS_ERR_NONE;
}