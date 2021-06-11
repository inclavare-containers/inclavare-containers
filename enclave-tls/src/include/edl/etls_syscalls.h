#ifndef _ETLS_SYSCALL_H_
#define _ETLS_SYSCALL_H_

#include <sys/types.h>

struct etls_dirent
{
	u_int64_t d_ino;
	int64_t d_off; //off_t
	u_int16_t d_reclen;
	u_int8_t d_type;
	char d_name[256]; // NAME_MAX + 1 = 256
};

#endif
