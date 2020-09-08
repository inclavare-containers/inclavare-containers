package occlum

import (
	cache_manager "github.com/alibaba/inclavare-containers/epm/pkg/epm"
)

type BundleCach0Manager struct {
	cache_manager.DefaultEnclavePool
}

func (d *BundleCach0Manager) GetPoolType() string {
	return "bundle-cache.occlum.cache0"
}

type BundleCach1Manager struct {
	cache_manager.DefaultEnclavePool
}

func (d *BundleCach1Manager) GetPoolType() string {
	return "bundle-cache.occlum.cache1"
}

type BundleCach2Manager struct {
	cache_manager.DefaultEnclavePool
}

func (d *BundleCach2Manager) GetPoolType() string {
	return "bundle-cache.occlum.cache2"
}
