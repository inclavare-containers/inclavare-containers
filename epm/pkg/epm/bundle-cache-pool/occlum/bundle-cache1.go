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

type BundleCache1Manager struct {
	cache_manager.DefaultEnclavePool
}

func NewBundleCache1Manager(root string, metadata *cache_metadata.Metadata) *BundleCache1Manager {
	return &BundleCache1Manager{
		DefaultEnclavePool: cache_manager.DefaultEnclavePool{
			Root:          root,
			Type:          string(types.BundleCache1PoolType),
			CacheMetadata: metadata,
		}}
}

func (d *BundleCache1Manager) GetPoolType() string {
	return d.Type
}

func (d *BundleCache1Manager) SaveCache(sourcePath string, cache *v1alpha1.Cache) error {
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

	sourceDirs := []string{
		"build/bin/",
		"build/lib/",
		"run/",
		"build/initfs",
	}
	sourceFiles := []string{
		"Occlum.json",
		"build/Enclave.xml",
		"build/Occlum.json",
		"build/Occlum.json.protected",
		"build/image_config.json",
		"build/.Occlum_sys.json",
		"build/.Occlum_sys.json.protected",
	}
	for _, dir := range sourceDirs {
		srcDir := filepath.Join(sourcePath, dir)
		destDir := filepath.Join(savePath, dir)
		src, err := os.Stat(srcDir)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(destDir, src.Mode()); err != nil {
			return err
		}
		if err := utils.CopyDirectory(srcDir, destDir); err != nil {
			return err
		}
	}
	for _, file := range sourceFiles {
		if err := utils.CopyFile(filepath.Join(sourcePath, file), filepath.Join(savePath, file)); err != nil {
			return err
		}
	}
	if err := ioutil.WriteFile(filepath.Join(savePath, constants.OcclumStatusFileName), []byte(types.Built), 0644); err != nil {
		return err
	}

	os.Remove(filepath.Join(savePath, "build/lib/libocclum-libos.signed.so"))

	size, err := utils.DirSize(savePath)
	if err != nil {
		return err
	}
	cache.SavePath = savePath
	cache.Size = size
	cache.Created = time.Now().Unix()
	return d.CacheMetadata.SaveCache(d.GetPoolType(), cache.ID, cache)
}
