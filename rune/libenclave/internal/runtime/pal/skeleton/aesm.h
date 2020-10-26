/* *INDENT-OFF* */
#ifndef AESMD_H
#define AESMD_H
/* *INDENT-ON* */

#include <stdbool.h>
#include "defines.h"

bool get_launch_token(struct sgx_sigstruct *sigstruct,
		      struct sgx_einittoken *token);

/* *INDENT-OFF* */
#endif
/* *INDENT-ON* */
