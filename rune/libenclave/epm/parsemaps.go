package epm

import (
	"github.com/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/sirupsen/logrus"
)

func GetParseMaps(pid int) *v1alpha1.Enclave {
	var enclavelayout v1alpha1.Enclave
	enclavelayout.Layout = make([]*v1alpha1.Enclavelayout, 32)
	fd, err := GetEnclaveFd(pid)
	enclavemaps, err := GetEnclProcMaps(pid)
	if err != nil {
		logrus.Fatal(err)
	}

	enclavelayout.Fd = int64(fd)
	enclavelayout.Nr = int64(len(enclavemaps))

	for i, maps := range enclavemaps {
		enclavelayout.Layout[i] = new(v1alpha1.Enclavelayout)
		enclavelayout.Layout[i].Addr = uint64(maps.StartAddr)
		enclavelayout.Layout[i].Size = uint64(maps.EndAddr - maps.StartAddr)
		enclavelayout.Layout[i].Prot = new(v1alpha1.EnclavePerms)
		enclavelayout.Layout[i].Prot.Read = maps.Perms.Read
		enclavelayout.Layout[i].Prot.Write = maps.Perms.Write
		enclavelayout.Layout[i].Prot.Execute = maps.Perms.Execute
		enclavelayout.Layout[i].Prot.Private = maps.Perms.Private
		enclavelayout.Layout[i].Prot.Share = maps.Perms.Shared
	}

	return &enclavelayout
}
