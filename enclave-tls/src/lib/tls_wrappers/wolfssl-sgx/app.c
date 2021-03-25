#include "app.h"
#include <stdio.h>

void *memmem(void *start, unsigned int s_len, void *find, unsigned int f_len)
{
	char *p, *q;
	unsigned int len;
	p = start, q = find;
	len = 0;
	while((p - (char *)start + f_len) <= s_len){
		while(*p++ == *q++){
			len++;
			if(len == f_len)
				return(p - f_len);
		};
		q = find;
		len = 0;
	};
	return(NULL);
}

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

