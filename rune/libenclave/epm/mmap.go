package epm

/*
#cgo linux LDFLAGS: -lrt

#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>

uintptr_t mmap(uintptr_t, uintptr_t, int, int, int, long long);
*/
import "C"

import (
	"syscall"

	"github.com/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/sirupsen/logrus"
)

func SgxMmap(enclaveinfo v1alpha1.Enclave) error {
	var err error
	fd := enclaveinfo.Fd
	for i := 0; i < int(enclaveinfo.Nr); i++ {
		prot := 0
		flags := 0
		enclavelayout := enclaveinfo.Layout[i]
		if enclavelayout.Prot.Read == true {
			prot |= 1 << 0
		}
		if enclavelayout.Prot.Write == true {
			prot |= 1 << 1
		}
		if enclavelayout.Prot.Execute == true {
			prot |= 1 << 2
		}
		if enclavelayout.Prot.Private == true {
			flags |= 1 << 1
		}
		if enclavelayout.Prot.Share == true {
			flags |= 1 << 0
		}

		flags = flags | syscall.MAP_FIXED
		_, err = C.mmap(C.uintptr_t(enclavelayout.Addr), C.uintptr_t(enclavelayout.Size), C.int(prot), C.int(flags), C.int(fd), 0)
		if nil != err {
			logrus.Warnf("mmap fail!!!", err)
			return err
		}
	}
	return err
}
