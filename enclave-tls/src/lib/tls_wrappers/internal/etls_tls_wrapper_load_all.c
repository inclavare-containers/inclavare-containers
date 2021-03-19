#include <string.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>

#include "internal/tls_wrapper.h"

int tls_wrapper_cmp(const void *a, const void *b)
{
	return (*(tls_wrapper_ctx_t **) b)->opts->priority -
		(*(tls_wrapper_ctx_t **) a)->opts->priority;
}

enclave_tls_err_t etls_tls_wrapper_load_all(void)
{
	ETLS_DEBUG("called\n");

	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;

	DIR *dir;
	struct dirent *ptr;

	if ((dir = opendir(TLS_WRAPPERS_PATH)) == NULL) {
		ETLS_ERR("Open '%s' error", TLS_WRAPPERS_PATH);
		return -ENCLAVE_TLS_ERR_UNKNOWN;
	}

	int total_num = 0;
	int err_num = 0;
	while ((ptr = readdir(dir)) != NULL) {
		if (strcmp(ptr->d_name, ".") == 0 ||
		    strcmp(ptr->d_name, "..") == 0)
			continue;
		else if (ptr->d_type == 8) {
			total_num++;
			err = etls_tls_wrapper_load_single(ptr->d_name);
			if (err != ENCLAVE_TLS_ERR_NONE)
				err_num++;
		}
	}

	if (total_num == err_num) {
		ETLS_ERR("ERROR: NO valid TLS Wrapper instance in %s\n",
			 TLS_WRAPPERS_PATH);
		closedir(dir);
		return -ENCLAVE_TLS_ERR_LOAD_TLS;
	}

	closedir(dir);

	/* Sort all enclave_quote_ctx_t instances in the enclave_quotes_ctx, and the higher priority
	 * instance should be sorted in front of the enclave_quotes_ctx array.
	 */
	qsort(tls_wrappers_ctx, tls_wrappers_nums, sizeof(tls_wrapper_ctx_t *),
	      tls_wrapper_cmp);

	return ENCLAVE_TLS_ERR_NONE;
}
