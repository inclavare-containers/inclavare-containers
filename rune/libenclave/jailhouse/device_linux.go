package jailhouse // import "github.com/inclavare-containers/rune/libenclave/jailhouse"

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	JailHouseDevice = "/dev/jailhouse"
)

func IsJailHouseSupported() bool {
	var stat unix.Stat_t
	err := unix.Lstat(JailHouseDevice, &stat)
	if err != nil {
		return false
	}

	devNumber := uint64(stat.Rdev)
	major := unix.Major(devNumber)
	if major != 10 {
		return false
	}

	if stat.Mode&unix.S_IFCHR != unix.S_IFCHR {
		return false
	}
	logrus.Debug("Jailhouse Enclave detected")

	return true
}
