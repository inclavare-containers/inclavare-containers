#include <stdarg.h>
#include <stdio.h>
#include "sgx_stub_t.h"

void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

int sprintf(char *buf, const char *fmt, ...)
{
	va_list ap;
	int ret;
	va_start(ap, fmt);
	ret = vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	return ret;
}

double current_time(void)
{
	double curr;
	ocall_current_time(&curr);
	return curr;
}

int LowResTimer(void)
{
	int time;
	ocall_low_res_time(&time);
	return time;
}
