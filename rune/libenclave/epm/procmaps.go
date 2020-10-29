package epm

import (
	"github.com/prometheus/procfs"
	"github.com/sirupsen/logrus"
)

const (
	EnclavePath = "/dev/sgx/enclave"
)

func GetEnclProcMaps(pid int) ([]*procfs.ProcMap, error) {
	var enclprocmaps []*procfs.ProcMap

	fs, err := procfs.NewFS("/proc")
	if err != nil {
		logrus.Fatal(err)
	}

	p, err := fs.Proc(pid)
	if err != nil {
		logrus.Fatal(err)
	}

	maps, err := p.ProcMaps()
	if err != nil {
		logrus.Fatal(err)
	}

	for idx := range maps {
		if maps[idx].Pathname == EnclavePath {
			enclprocmaps = append(enclprocmaps, maps[idx])
		}
	}

	return enclprocmaps, err
}

func GetEnclaveFd(pid int) (int, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		logrus.Fatal(err)
	}

	p, err := fs.Proc(pid)
	if err != nil {
		logrus.Fatal(err)
	}

	names, err := p.FileDescriptorTargets()
	if err != nil {
		logrus.Fatal(err)
	}

	for fd, n := range names {
		if n == EnclavePath {
			return int(fd), err
		}
	}

	return 0, err
}
