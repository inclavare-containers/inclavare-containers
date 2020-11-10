package enclave_runtime_pal // import "github.com/inclavare-containers/rune/libenclave/internal/runtime/pal"

/*
#cgo linux LDFLAGS: -ldl
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
*/
import "C"

import (
	"github.com/sirupsen/logrus"
	"unsafe"
)

var fptr_pal_get_version unsafe.Pointer
var fptr_pal_init unsafe.Pointer
var fptr_pal_exec unsafe.Pointer
var fptr_pal_kill unsafe.Pointer
var fptr_pal_destroy unsafe.Pointer
var fptr_pal_create_process unsafe.Pointer
var fptr_pal_get_local_report unsafe.Pointer

func Loadbinary(path string) {
	dl := C.dlopen(C.CString(path), C.RTLD_NOW)
	if dl == nil {
		logrus.Fatalf("failed to load %s, dlerror: %s", path, C.GoString(C.dlerror()))
	}

	fptr_pal_get_version = C.dlsym(dl, C.CString("pal_get_version"))
	fptr_pal_init = C.dlsym(dl, C.CString("pal_init"))
	fptr_pal_create_process = C.dlsym(dl, C.CString("pal_create_process"))
	fptr_pal_exec = C.dlsym(dl, C.CString("pal_exec"))
	fptr_pal_kill = C.dlsym(dl, C.CString("pal_kill"))
	fptr_pal_destroy = C.dlsym(dl, C.CString("pal_destroy"))
	fptr_pal_get_local_report = C.dlsym(dl, C.CString("pal_get_local_report"))
}

func symAddrPalVersion() unsafe.Pointer {
	return unsafe.Pointer(fptr_pal_get_version)
}

func symAddrPalInit() unsafe.Pointer {
	return unsafe.Pointer(fptr_pal_init)
}

func symAddrPalExec() unsafe.Pointer {
	return unsafe.Pointer(fptr_pal_exec)
}

func symAddrPalKill() unsafe.Pointer {
	return unsafe.Pointer(fptr_pal_kill)
}

func symAddrPalDestroy() unsafe.Pointer {
	return unsafe.Pointer(fptr_pal_destroy)
}

func symAddrPalGetLocalReport() unsafe.Pointer {
	return unsafe.Pointer(fptr_pal_get_local_report)
}

func symAddrPalCreateProcess() unsafe.Pointer {
	return unsafe.Pointer(fptr_pal_create_process)
}
