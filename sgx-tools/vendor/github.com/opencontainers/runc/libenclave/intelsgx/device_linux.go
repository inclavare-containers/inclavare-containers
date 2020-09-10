package intelsgx // import "github.com/opencontainers/runc/libenclave/intelsgx"

/*
#cgo linux LDFLAGS: -ldl
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
*/
import "C"

import (
	"unsafe"
)

func loadLibrary(p string) {
	path := C.CString(p)
	dl := C.dlopen(path, C.RTLD_NOW)
	if dl == nil {
		C.perror(C.CString("failed to load library " + p))
	}
	C.free(unsafe.Pointer(path))
}

// Due to the design of runelet, the Enclave Runtime PAL is loaded
// in host but launched in container. The fact that certain libraries
// from Intel SGX PSW would use dlopen() to further load
// libsgx_launch.so, which means the container has to have it. In
// order to ensure all libraries dependent by Enclave Runtime PAL
// are completely loaded in host, preload them prior to switch
// into container.
func preloadSgxPswLib() {
	loadLibrary("libsgx_launch.so.1")
}

func init() {
	preloadSgxPswLib()
}
