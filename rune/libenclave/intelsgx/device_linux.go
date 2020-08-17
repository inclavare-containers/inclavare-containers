package intelsgx // import "github.com/inclavare-containers/rune/libenclave/intelsgx"

/*
#cgo linux LDFLAGS: -ldl
#include <stdlib.h>
#include <dlfcn.h>
*/
import "C"

import (
	"unsafe"
)

// Due to the design of runelet, the Enclave Runtime PAL is loaded
// in host but launched in container. The fact that certain libraries
// from Intel SGX PSW would use dlopen() to further load
// libsgx_launch.so, which means the container has to have it. In
// order to ensure all libraries dependent by Enclave Runtime PAL
// are completely loaded in host, preload them prior to switch
// into container.
func preloadSgxPswLib() {
	path := C.CString("libsgx_launch.so")
	C.dlopen(path, C.RTLD_NOW)
	C.free(unsafe.Pointer(path))
}

func init() {
	preloadSgxPswLib()
}
