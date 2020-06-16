// +build linux

package nsenter

/*
#cgo LDFLAGS: -ldl

#include <stdio.h>
#include <stdlib.h>

struct pal_attr_t {
	const char *args;
	const char *log_level;
};

struct pal_stdio_fds {
	int stdin, stdout, stderr;
};

extern int *pal_version;
extern int (*fptr_pal_init)(const struct pal_attr_t *attr);
extern int (*fptr_pal_exec)(const char *path, const char * const argv[],
			const struct pal_stdio_fds *stdio, int *exit_code);
extern int (*fptr_pal_kill)(int sig, int pid);
extern int (*fptr_pal_destroy)(void);
*/
import "C"

import (
	"unsafe"
)

func SymAddrPalVersion() unsafe.Pointer {
	return unsafe.Pointer(C.pal_version)
}

func SymAddrPalInit() unsafe.Pointer {
	return unsafe.Pointer(C.fptr_pal_init)
}

func SymAddrPalExec() unsafe.Pointer {
	return unsafe.Pointer(C.fptr_pal_exec)
}

func SymAddrPalKill() unsafe.Pointer {
	return unsafe.Pointer(C.fptr_pal_kill)
}

func SymAddrPalDestroy() unsafe.Pointer {
	return unsafe.Pointer(C.fptr_pal_destroy)
}
