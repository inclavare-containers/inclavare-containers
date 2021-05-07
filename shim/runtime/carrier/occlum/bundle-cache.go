package occlum

import (
	"crypto/md5"
	"fmt"
	"os"

	epm_api "github.com/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/inclavare-containers/epm/pkg/epm/bundle-cache-pool/occlum/types"
	"github.com/inclavare-containers/shim/runtime/utils"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type bundleCacheConfig struct {
	epmConnection *grpc.ClientConn
	cacheLevel    types.BundleCachePoolType
	cacheIDMap    map[types.BundleCachePoolType]string
	inputsCache   inputsCache
}

type inputsCache struct {
	inputs0 bundleCache0Inputs
	inputs1 bundleCache1Inputs
	inputs2 bundleCache2Inputs
}

type cacheInputs interface {
	buildID() (string, error)
}

type bundleCache0Inputs struct {
	imageDigest string
}

type bundleCache1Inputs struct {
	bundleCache0Inputs
	occlumLibOSPath  string
	occlumConfigPath string
}

type bundleCache2Inputs struct {
	bundleCache1Inputs
	publicKeyFilePath string
}

func (b *bundleCache0Inputs) buildID() (string, error) {
	return b.imageDigest, nil
}

func (b *bundleCache1Inputs) buildID() (string, error) {
	bundleCache0Md5, err := b.bundleCache0Inputs.buildID()
	if err != nil {
		return "", err
	}
	occlumLibOSMd5, err := utils.Md5File(b.occlumConfigPath)
	if err != nil {
		return "", err
	}
	occlumConfigMd5, err := utils.Md5File(b.occlumConfigPath)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s-%s-%s", bundleCache0Md5, occlumLibOSMd5, occlumConfigMd5)))), nil
}

func (b *bundleCache2Inputs) buildID() (string, error) {
	bundleCache1Md5, err := b.bundleCache1Inputs.buildID()
	if err != nil {
		return "", err
	}
	publicKeyMd5, err := utils.Md5File(b.publicKeyFilePath)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%s-%s", bundleCache1Md5, publicKeyMd5)))), nil
}

func (o *occlum) loadBundleCache(typ types.BundleCachePoolType, inputs cacheInputs, targetPath string) (string, error) {
	cacheId, err := inputs.buildID()
	if err != nil {
		return "", err
	}
	logrus.Debugf("loadBundleCache: cacheId: %s, type: %s", cacheId, typ)
	return o.loadBundleCacheByCacheId(typ, cacheId, targetPath)
}

func (o *occlum) loadBundleCacheByCacheId(typ types.BundleCachePoolType, cacheId string, targetPath string) (string, error) {
	if o.bundleCacheConfig.epmConnection == nil {
		return "", fmt.Errorf("epm client is not exit")
	}
	if err := os.MkdirAll(targetPath, 0755); err != nil {
		return "", err
	}
	cli := epm_api.NewEnclavePoolManagerClient(o.bundleCacheConfig.epmConnection)
	resp, err := cli.LoadCache(o.context, &epm_api.LoadCacheRequest{
		Type:       string(typ),
		ID:         cacheId,
		TargetPath: targetPath,
	})
	if err != nil {
		return "", err
	}
	if !resp.Ok {
		return "", fmt.Errorf("load bundle cache failed. type: %s", typ)
	}
	return cacheId, nil
}

func (o *occlum) saveBundleCache(typ types.BundleCachePoolType, inputs cacheInputs,
	parent *epm_api.Cache, sourcePath string) (*epm_api.Cache, error) {
	cacheId, err := inputs.buildID()
	logrus.Debugf("saveBundleCache: cacheId: %s, type: %s", cacheId, typ)
	if err != nil {
		return nil, fmt.Errorf("build cacheID failed. type: %s, error: %++v", typ, err)
	}
	return o.saveBundleCacheByCacheId(typ, cacheId, parent, sourcePath)
}

func (o *occlum) saveBundleCacheByCacheId(typ types.BundleCachePoolType, cacheId string,
	parent *epm_api.Cache, sourcePath string) (*epm_api.Cache, error) {
	if o.bundleCacheConfig.epmConnection == nil {
		return nil, fmt.Errorf("epm client is not exit")
	}
	cli := epm_api.NewEnclavePoolManagerClient(o.bundleCacheConfig.epmConnection)
	cache := &epm_api.Cache{
		Type:   string(typ),
		ID:     cacheId,
		Parent: parent,
	}
	resp, err := cli.SaveCache(o.context, &epm_api.SaveCacheRequest{
		Cache:      cache,
		SourcePath: sourcePath,
	})
	if err != nil || !resp.Ok {
		return nil, fmt.Errorf("save bundle cache failed. error: %v, type: %s, cache: %v", err, typ, cache)
	}
	return cache, nil
}

func (o *occlum) deleteBundleCache(typ types.BundleCachePoolType, cacheId string) error {
	if o.bundleCacheConfig.epmConnection == nil {
		return fmt.Errorf("epm client is not exit")
	}
	cli := epm_api.NewEnclavePoolManagerClient(o.bundleCacheConfig.epmConnection)
	resp, err := cli.DeleteCache(o.context, &epm_api.DeleteCacheRequest{
		Type: string(typ),
		ID:   cacheId,
	})
	if err != nil || !resp.Ok {
		return fmt.Errorf("delete bundle cache failed. error: %v,  type: %s, id: %s", err, typ, cacheId)
	}
	return nil
}
