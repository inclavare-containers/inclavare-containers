package occlum

import (
	cache_manager "github.com/alibaba/inclavare-containers/epm/pkg/epm"
)

type Cach0Manager struct {
	cache_manager.DefaultCachePoolManager
}

func (d *Cach0Manager) GetCacheType() string {
	return "bundle-cache-pool.occlum.cache0"
}

type Cach1Manager struct {
	cache_manager.DefaultCachePoolManager
}

func (d *Cach1Manager) GetCacheType() string {
	return "bundle-cache-pool.occlum.cache1"
}

type Cach2Manager struct {
	cache_manager.DefaultCachePoolManager
}

func (d *Cach2Manager) GetCacheType() string {
	return "bundle-cache-pool.occlum.cache2"
}
