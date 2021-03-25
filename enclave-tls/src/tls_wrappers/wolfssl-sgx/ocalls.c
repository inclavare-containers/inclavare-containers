#include <stdio.h>
#include "sgx_stub_u.h"
#include "../wolfssl/oid.c"
#include "../wolfssl/un_negotiate.c"

static double current_time()
{
        struct timeval tv;

        gettimeofday(&tv, NULL);

        return (double)(1000000 * tv.tv_sec + tv.tv_usec) / 1000000.0;
}

void ocall_print_string(const char *str)
{
        /* Proxy/Bridge will check the length and null-terminate
         * the input string to prevent buffer overflow.
         */
        printf("%s", str);
}

void ocall_current_time(double *time)
{
        if (!time)
                return;

        *time = current_time();

        return;
}

void ocall_low_res_time(int *time)
{
        if (!time)
                return;

        struct timeval tv;
        *time = tv.tv_sec;
}

size_t ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
        return recv(sockfd, buf, len, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
        return send(sockfd, buf, len, flags);
}

int ocall_verify_certificate(uint8_t *der_crt, uint32_t der_crt_len)
{
	printf ("der_crt  %p, der_crt_len %d\n", der_crt, der_crt_len);
	return verify_certificate(der_crt, der_crt_len);
}
