#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/core.h"
#include "internal/crypto_wrapper.h"

#define PATTERN_PREFIX          "libcrypto_wrapper_"
#define PATTERN_SUFFIX          ".so"

/* *INDENT-OFF* */
enclave_tls_err_t etls_crypto_wrapper_load_single(const char *path)
{
	if (!path)
		return -ENCLAVE_TLS_ERR_INVALID;

	ETLS_DEBUG("loading crypto wrapper instance '%s'\n", path);

	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;

	/* Check whether the filename pattern matches up libcrypto_wrapper_<type>.so */
	if (strlen(path) <= strlen(PATTERN_PREFIX) + strlen(PATTERN_SUFFIX) ||
	    strncmp(path, PATTERN_PREFIX, strlen(PATTERN_PREFIX)) ||
	    strncmp(path + strlen(path) - strlen(PATTERN_SUFFIX), PATTERN_SUFFIX, strlen(PATTERN_SUFFIX))) {
		ETLS_DEBUG("The filename pattern of '%s' NOT match " PATTERN_PREFIX "<type>" PATTERN_SUFFIX "\n",
			   path);
		return -ENCLAVE_TLS_ERR_INVALID;
	}

	char realpath[strlen(CRYPTO_WRAPPERS_PATH) + strlen(path) + 1];
	sprintf(realpath, "%s%s", CRYPTO_WRAPPERS_PATH, path);

	void *handle = dlopen(realpath, RTLD_LAZY);
	if (!handle) {
		ETLS_ERR("failed on dlopen(): %s\n", dlerror());
		return -ENCLAVE_TLS_ERR_DLOPEN;
	}

	size_t type_len = strlen(path) - strlen(PATTERN_PREFIX) - strlen(PATTERN_SUFFIX);
	char type[type_len + 1];
	strncpy(type, path + strlen(PATTERN_PREFIX), type_len);
	type[type_len] = '\0';

	unsigned int i = 0;
	crypto_wrapper_opts_t *opts = NULL;

	for (i = 0; i < registerd_crypto_wrapper_nums; ++i) {
		opts = crypto_wrappers_opts[i];

		if (!strcmp(type, opts->type))
			break;
	}

	if (i == registerd_crypto_wrapper_nums) {
		ETLS_ERR("the constructor of crypto wrapper '%s' does NOT call crypto_wrapper_register()\n", type);
		return -ENCLAVE_TLS_ERR_NO_REGISTER;
	}

	err = opts->pre_init();
	if (err != CRYPTO_WRAPPER_ERR_NONE) {
		ETLS_ERR("failed on pre_init() of crypto wrapper '%s' with %#x\n", type, err);
		return err;
	}

	crypto_wrapper_ctx_t *crypto_ctx = calloc(1, sizeof(*crypto_ctx));
	if (!crypto_ctx)
		return -ENCLAVE_TLS_ERR_NO_MEM;

	crypto_ctx->opts = opts;
	crypto_ctx->conf_flags = global_core_context.config.flags;
	crypto_ctx->log_level = global_core_context.config.log_level;
	crypto_ctx->handle = handle;

	crypto_wrappers_ctx[crypto_wrappers_nums++] = crypto_ctx;

	ETLS_DEBUG("the crypto wrapper '%s' loaded\n", type);

	return ENCLAVE_TLS_ERR_NONE;
}
/* *INDENT-ON* */
