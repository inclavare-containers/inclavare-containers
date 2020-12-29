package types

type OcclumStatus string

const (
	ImageBuilt OcclumStatus = "image built"
	LibOSBuilt OcclumStatus = "libos built"
	Init       OcclumStatus = "init"
	Built      OcclumStatus = "built"
	Running    OcclumStatus = "running"
)

type BundleCachePoolType string

const (
	BundleCache0PoolType BundleCachePoolType = "bundle-cache.occlum.cache0"
	BundleCache1PoolType BundleCachePoolType = "bundle-cache.occlum.cache1"
	BundleCache2PoolType BundleCachePoolType = "bundle-cache.occlum.cache2"
)
