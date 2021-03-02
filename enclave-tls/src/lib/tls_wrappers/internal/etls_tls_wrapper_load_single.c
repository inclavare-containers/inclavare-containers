#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>

#include "internal/core.h"
#include "internal/tls_wrapper.h"

/* *INDENT-OFF* */
enclave_tls_err_t etls_tls_wrapper_load_single(const char *path)
{
	ETLS_DEBUG("etls_tls_wrapper_load_single() loaded tls wrapper: '%s'\n",
		   path);

	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;

	/* Checkt whether the format of path is libtls_wrapper_<type>.so */
	if ((memcmp(path, "libtls_wrapper_", strlen("libtls_wrapper_")) !=
	     0) || (memcmp(path + strlen(path) - 3, ".so", 3) != 0)) {
		ETLS_DEBUG("The format of '%s' NOT match libtls_wrapper_<type>.so\n",
			 path);
		return -ENCLAVE_TLS_ERR_INVALID;
	}

	char *realpath = (char *) malloc(strlen(TLS_WRAPPERS_PATH) + strlen("/") + strlen(path) + 1);
	if (!realpath) {
		return -ENCLAVE_TLS_ERR_NO_MEM;
	}
	sprintf(realpath, "%s%s%s", TLS_WRAPPERS_PATH, "/", path);
	void *handle = dlopen(realpath, RTLD_LAZY);
	if (NULL == handle) {
		ETLS_ERR("dlopen - %s\n", dlerror());
		free(realpath);
		return -ENCLAVE_TLS_ERR_DLOPEN;
	}

	size_t type_len = strlen(path) - 18;
	char *type = malloc(type_len + 1);
	if (!type) {
		free(realpath);
		return -ENCLAVE_TLS_ERR_NO_MEM;
	}
	memcpy(type, path + 15, type_len);
	type[type_len] = '\0';

	unsigned int i = 0;
	tls_wrapper_opts_t *tls_opts;
	for (i = 0; i < registerd_tls_wrapper_nums; ++i) {
		tls_opts = tls_wrappers_opts[i];

		if (strcmp(type, tls_opts->type))
			continue;

		tls_wrapper_err_t err = tls_opts->pre_init();
		if (err != TLS_WRAPPER_ERR_NONE) {
			ETLS_ERR("ERROR: tls_opts->pre_init()\n", path);
			goto err;
		}
		break;
	}

	if (i == registerd_tls_wrapper_nums) {
		ETLS_ERR("The constructor of %s does NOT call tls_wrapper_register\n", path);
		err = -ENCLAVE_TLS_ERR_NO_REGISTER;
		goto err;
	}

	tls_wrapper_ctx_t *tls_ctx = calloc(1, sizeof(*tls_ctx));
	if (!tls_ctx) {
		err = -ENCLAVE_TLS_ERR_NO_MEM;
		goto err;
	}
	tls_ctx->opts = tls_opts;
	tls_ctx->conf_flags = global_core_context.config.flags;
	tls_ctx->log_level = global_core_context.config.log_level;
	tls_ctx->handle = handle;

	tls_wrappers_ctx[tls_wrappers_nums++] = tls_ctx;

	free(realpath);
	free(type);

	return ENCLAVE_TLS_ERR_NONE;

err:
	free(realpath);
	free(type);
	return err;
}
/* *INDENT-ON* */
