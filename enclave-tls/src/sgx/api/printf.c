#include <stdio.h>
#include <string.h>
#include <enclave-tls/sgx.h>

int printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	char buf[PRINT_BUF_SIZE];
	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	buf[PRINT_BUF_SIZE - 1] = '\0';

	va_end(ap);

	sgx_ocall_print_string(buf);

	return (int)strnlen(buf, PRINT_BUF_SIZE - 1) + 1;
}
