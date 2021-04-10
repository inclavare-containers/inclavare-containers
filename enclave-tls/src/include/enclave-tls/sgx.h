#ifndef _ENCLAVE_SGX_H_
#define _ENCLAVE_SGX_H_

#define fprintf(stream, fmt, ...) \
	printf(fmt, ##__VA_ARGS__)

extern void printf(const char *fmt, ...);
#endif
