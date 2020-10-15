package libenclave // import "github.com/inclavare-containers/rune/libenclave"

import (
	"github.com/inclavare-containers/rune/libenclave/configs"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"net"
	"os/user"
)

var (
	enclaveHwType string = ""
)

func IsEnclaveEnabled(e *configs.Enclave) bool {
	if e == nil {
		return false
	}

	if !IsEnclaveHwEnabled(e.Type) {
		return false
	}

	return true
}

// Check whether enclave-based hardware is supported or not
func IsEnclaveHwEnabled(etype string) bool {
	if etype == "" && enclaveHwType != "" {
		return true
	}

	return etype == enclaveHwType
}

func init() {
	// initialize nss libraries in Glibc so that the dynamic libraries are loaded in the host
	// environment not in the chroot from untrusted files.
	_, _ = user.Lookup("")
	_, _ = net.LookupHost("")

	if intelsgx.IsSgxSupported() {
		enclaveHwType = configs.EnclaveHwIntelSgx
	}
}
