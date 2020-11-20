package nitroenclaves // import "github.com/inclavare-containers/rune/libenclave/nitroenclaves"

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	NitroEnclavesDevice = "/dev/nitro_enclaves"
)

func IsNitroEnclaves() bool {
	var stat unix.Stat_t
	err := unix.Lstat(NitroEnclavesDevice, &stat)
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
	logrus.Debug("AWS Nitro Enclaves detected")

	return true
}
