#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>

#include "internal/enclave_quote.h"
#include "internal/core.h"

/* *INDENT-OFF* */
enclave_tls_err_t etls_enclave_quote_load_single(const char *path)
{
	ETLS_DEBUG("etls_enclave_quote_load_single() loaded enclave quote: '%s'\n",
		 path);

	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;

	/* Checkt whether the format of path is libenclave_quote_<type>.so */
	if ((memcmp(path, "libenclave_quote_", strlen("libenclave_quote_")) !=
	     0) || (memcmp(path + strlen(path) - 3, ".so", 3) != 0)) {
		ETLS_DEBUG("The format of '%s' NOT match libenclave_quote_<type>.so\n",
			 path);
		return -ENCLAVE_TLS_ERR_INVALID;
	}

	char *realpath = (char *) malloc(strlen(ENCLAVE_QUOTES_PATH) + strlen("/") + strlen(path));
	if (!realpath) {
		return -ENCLAVE_TLS_ERR_NO_MEM;
	}
	sprintf(realpath, "%s%s%s", ENCLAVE_QUOTES_PATH, "/", path);
	void *handle = dlopen(realpath, RTLD_LAZY);
	if (NULL == handle) {
		ETLS_ERR("dlopen - %s\n", dlerror());
		free(realpath);
		return -ENCLAVE_TLS_ERR_DLOPEN;
	}

	/* Get the type of quote instance */
	size_t type_len = strlen(path) - 20;
	char *type = malloc(type_len + 1);
	if (!type) {
		free(realpath);
		return -ENCLAVE_TLS_ERR_NO_MEM;
	}
	memcpy(type, path + 17, type_len);
	type[type_len] = '\0';

	unsigned int i = 0;
	enclave_quote_opts_t *quote_opts;
	for (i = 0; i < registerd_enclave_quote_nums; ++i) {
		quote_opts = enclave_quotes_opts[i];

		if (strcmp(type, quote_opts->type))
			continue;

		enclave_quote_err_t err = quote_opts->pre_init();
		if (err != ENCLAVE_QUOTE_ERR_NONE) {
			ETLS_ERR("ERROR: quote_opts->pre_init()\n", path);
			goto err;
		}
		break;
	}

	if (i == registerd_enclave_quote_nums) {
		ETLS_ERR("The constructor of %s does NOT call tls_wrapper_register\n", path);
		err = -ENCLAVE_TLS_ERR_NO_REGISTER;
		goto err;
	}

	enclave_quote_ctx_t *quote_ctx = calloc(1, sizeof(*quote_ctx));
	if (!quote_ctx) {
		err = -ENCLAVE_TLS_ERR_NO_MEM;
		goto err;
	}
	quote_ctx->opts = quote_opts;
	quote_ctx->log_level = global_core_context.config.log_level;
	quote_ctx->handle = handle;
	enclave_quotes_ctx[enclave_quote_nums++] = quote_ctx;

	free(realpath);
	free(type);

	return ENCLAVE_TLS_ERR_NONE;

err:
	free(realpath);
	free(type);
	return err;
}
/* *INDENT-ON* */
