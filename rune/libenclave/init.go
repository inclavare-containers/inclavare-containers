package libenclave // import "github.com/inclavare-containers/rune/libenclave"

import (
	"github.com/inclavare-containers/rune/libenclave/configs"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/inclavare-containers/rune/libenclave/nitroenclaves"
	"net"
	"os/user"
)

var (
	enclaveType string = ""
)

func IsEnclaveEnabled(e *configs.Enclave) bool {
	if e == nil {
		return false
	}

	if !IsProbedEnclaveEnabled(e.Type) {
		return false
	}

	return true
}

// Check whether enclave probed is supported or not
func IsProbedEnclaveEnabled(etype string) bool {
	if etype == "" && enclaveType != "" {
		return true
	}

	return etype == enclaveType
}

func init() {
	// initialize nss libraries in Glibc so that the dynamic libraries are loaded in the host
	// environment not in the chroot from untrusted files.
	_, _ = user.Lookup("")
	_, _ = net.LookupHost("")

	if intelsgx.IsSgxSupported() {
		enclaveType = configs.EnclaveTypeIntelSgx
	} else if nitroenclaves.IsNitroEnclaves() {
		enclaveType = configs.EnclaveTypeAwsNitroEnclaves
	}
}
