#ifndef _RTLS_SOCKET_H_
#define _RTLS_SOCKET_H_

#include <sys/types.h>

// clang-format off
#define RTLS_AF_INET            2
#define RTLS_SOCK_STREAM        1
#define RTLS_SOL_SOCKET         1
#define RTLS_SO_REUSEADDR       2
// clang-format on

/* Define in_addr */
struct rtls_in_addr {
	uint32_t s_addr;
};

/* Define sockaddr_in */
struct rtls_sockaddr_in {
	uint16_t sin_family;
	uint16_t sin_port;
	struct rtls_in_addr sin_addr;
	uint8_t sin_zero[8];
};

/* Define sockaddr */
struct rtls_sockaddr {
	uint16_t sa_family;
	char sa_data[14];
};

#endif
