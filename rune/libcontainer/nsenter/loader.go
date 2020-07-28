// +build linux

package nsenter

/*
#cgo LDFLAGS: -ldl

#include <stdio.h>
#include <stdlib.h>

extern void *fptr_pal_get_version;
extern void *fptr_pal_init;
extern void *fptr_pal_exec;
extern void *fptr_pal_kill;
extern void *fptr_pal_destroy;
extern void *fptr_pal_create_process;
extern void *fptr_pal_get_local_report;
*/
import "C"

import (
	"unsafe"
)

func SymAddrPalVersion() unsafe.Pointer {
	return unsafe.Pointer(C.fptr_pal_get_version)
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

func SymAddrPalGetLocalReport() unsafe.Pointer {
	return unsafe.Pointer(C.fptr_pal_get_local_report)
}

func SymAddrPalCreateProcess() unsafe.Pointer {
	return unsafe.Pointer(C.fptr_pal_create_process)
}
