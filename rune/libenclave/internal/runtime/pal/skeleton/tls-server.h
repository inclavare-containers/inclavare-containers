/* *INDENT-OFF* */
#ifndef TLS_SERVER_H
#define TLS_SERVER_H
/* *INDENT-ON* */

#include <stdbool.h>

extern bool tls_server;

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
