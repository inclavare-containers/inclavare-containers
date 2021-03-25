#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/enclave_quote.h"

int enclave_quote_cmp(const void *a, const void *b)
{
	return (*(enclave_quote_ctx_t **) b)->opts->priority -
		(*(enclave_quote_ctx_t **) a)->opts->priority;
}

enclave_tls_err_t etls_enclave_quote_load_all(void)
{
	ETLS_DEBUG("called\n");

	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;

	DIR *dir;
	struct dirent *ptr;

	if ((dir = opendir(ENCLAVE_QUOTES_PATH)) == NULL) {
		ETLS_ERR("Open '%s' error", ENCLAVE_QUOTES_PATH);
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
			err = etls_enclave_quote_load_single(ptr->d_name);
			if (err != ENCLAVE_TLS_ERR_NONE)
				err_num++;
		}
	}

	if (total_num == err_num) {
		ETLS_ERR("ERROR: NO valid Enclave Quote instance in %s\n",
			 ENCLAVE_QUOTES_PATH);
		closedir(dir);
		return -ENCLAVE_TLS_ERR_LOAD_QUOTE;
	}

	closedir(dir);

	/* Sort all enclave_quote_ctx_t instances in the enclave_quotes_ctx, and the higher priority
	 * instance should be sorted in front of the enclave_quotes_ctx array.
	 */
	qsort(enclave_quotes_ctx, enclave_quote_nums,
	      sizeof(enclave_quote_ctx_t *), enclave_quote_cmp);

	return ENCLAVE_TLS_ERR_NONE;
}
