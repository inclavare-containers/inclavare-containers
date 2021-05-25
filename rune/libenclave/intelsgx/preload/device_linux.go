package preload // import "github.com/inclavare-containers/rune/libenclave/intelsgx/preload"

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
// from Intel SGX PSW would use dlopen() to further load supporting
// libraries, which means the container has to contain them. In order
// to ensure all libraries dependent by Enclave Runtime PAL are completely
// loaded in host, preload them prior to switch into container.
func preloadSgxPswLib() {
	// Required for launch token generation for non-FLC platform
	loadLibrary("libsgx_launch.so.1")

	// Required for EPID-based remote attestation
	loadLibrary("libsgx_epid.so.1")

	// Required for ECDSA-based remote attestation
	loadLibrary("libdcap_quoteprov.so.1")
	loadLibrary("libsgx_default_qcnl_wrapper.so.1")
	loadLibrary("libsgx_urts.so.1")
}

func PreloadLib() {
	preloadSgxPswLib()
}
