package occlum

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	cache_manager "github.com/inclavare-containers/epm/pkg/epm"
	"github.com/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/inclavare-containers/epm/pkg/epm/bundle-cache-pool/occlum/constants"
	"github.com/inclavare-containers/epm/pkg/epm/bundle-cache-pool/occlum/types"
	cache_metadata "github.com/inclavare-containers/epm/pkg/metadata"
	"github.com/inclavare-containers/epm/pkg/utils"
)

type BundleCache2Manager struct {
	cache_manager.DefaultEnclavePool
}

func NewBundleCache2Manager(root string, metadata *cache_metadata.Metadata) *BundleCache2Manager {
	return &BundleCache2Manager{
		DefaultEnclavePool: cache_manager.DefaultEnclavePool{
			Root:          root,
			Type:          string(types.BundleCache2PoolType),
			CacheMetadata: metadata,
		}}
}

func (d *BundleCache2Manager) GetPoolType() string {
	return d.Type
}

func (d *BundleCache2Manager) SaveCache(sourcePath string, cache *v1alpha1.Cache) error {
	savePath, err := d.BuildCacheSavePath(d.Root, cache)
	if err != nil {
		return fmt.Errorf("build cache save path failed. error: %++v", err)
	}
	if err := os.RemoveAll(savePath); err != nil {
		return nil
	}
	if err := os.MkdirAll(savePath, 0755); err != nil {
		return err
	}

	sourceFiles := []string{
		"build/lib/libocclum-libos.signed.so",
	}
	for _, file := range sourceFiles {
		srcFile := filepath.Join(sourcePath, file)
		destFile := filepath.Join(savePath, file)
		srcDir, err := os.Stat(filepath.Dir(srcFile))
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destFile), srcDir.Mode()); err != nil {
			return err
		}
		if err := utils.CopyFile(srcFile, destFile); err != nil {
			return err
		}
	}
	if err := ioutil.WriteFile(filepath.Join(savePath, constants.OcclumStatusFileName), []byte(types.Built), 0644); err != nil {
		return err
	}

	size, err := utils.DirSize(savePath)
	if err != nil {
		return err
	}
	cache.SavePath = savePath
	cache.Size = size
	cache.Created = time.Now().Unix()
	return d.CacheMetadata.SaveCache(d.GetPoolType(), cache.ID, cache)
}
