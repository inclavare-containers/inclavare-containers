/* *INDENT-OFF* */
#ifndef TLS_SERVER_H
#define TLS_SERVER_H
/* *INDENT-ON* */

#include <stdbool.h>

extern bool tls_server;
extern bool debugging;
extern char *attester_type;
extern char *verifier_type;
extern char *tls_type;
extern char *crypto;

#ifdef TLS_SERVER
extern int ra_tls_server(void);

#else

static inline int ra_tls_server(void)
{
	return 0;
}
#endif

/* *INDENT-OFF* */
#endif
/* *INDENT-ON* */
