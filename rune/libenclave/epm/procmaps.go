package epm

import (
	"github.com/prometheus/procfs"
	"github.com/sirupsen/logrus"
)

/* Once enclave is stored into pool, its pathname will be /sgx/enclave in
 * /proc/[epm pid]/fd and provide to rune side. When storing the enclave
 * into pool again from rune side, it need obtain enclave fd and enclave maps
 * info correctly by this kind of pathname.
 */
const (
	EnclavePath     = "/dev/sgx/enclave"
	EnclavePathPool = "/sgx/enclave"
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
		pathname := maps[idx].Pathname
		if pathname == EnclavePath || pathname == EnclavePathPool {
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
		if n == EnclavePath || n == EnclavePathPool {
			return int(fd), err
		}
	}

	return 0, err
}
