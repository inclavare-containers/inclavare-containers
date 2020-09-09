package epm

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alibaba/inclavare-containers/epm/pkg/utils"

	"github.com/alibaba/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	cache_metadata "github.com/alibaba/inclavare-containers/epm/pkg/metadata"
)

// EnclavePool represents a kind of enclave pool
type EnclavePool interface {
	// GetCache gets the cache by ID
	GetCache(ID string) (*v1alpha1.Cache, error)
	// SaveCache saves the data to a cache directory and record the cache metadata
	SaveCache(sourcePath string, cache *v1alpha1.Cache) error
	// ListCache lists part of or all of the cache metadata
	ListCache(lastCacheID string, limit int32) ([]*v1alpha1.Cache, error)
	// DeleteCache deletes the specified cached data and remove the corresponding cache metadata
	DeleteCache(ID string) error
	// LoadCache loads the specified cache data to work directory
	LoadCache(ID, targetPath string) error
	// GetPoolType gets the pool type of current pool
	GetPoolType() string
}

// DefaultEnclavePool is the default implementation of EnclavePool
type DefaultEnclavePool struct {
	Root          string
	CacheMetadata *cache_metadata.Metadata
}

func (d *DefaultEnclavePool) GetCache(ID string) (*v1alpha1.Cache, error) {
	return d.CacheMetadata.GetCache(d.GetPoolType(), ID)
}

func (d *DefaultEnclavePool) SaveCache(sourcePath string, cache *v1alpha1.Cache) error {
	savePath, err := d.BuildCacheSavePath(d.Root, cache)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(savePath); err != nil {
		return err
	}
	if err := os.MkdirAll(savePath, 755); err != nil {
		return err
	}
	if _, err := utils.ExecCmd("/bin/cp", []string{"-fr", sourcePath, savePath}); err != nil {
		return err
	}
	sizeStr, err := utils.ExecCmd("du", []string{"-sb", savePath, "|", "awk", "'{print $1}'"})
	if err != nil {
		return err
	}
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return err
	}
	cache.SavePath = savePath
	cache.Size = size
	cache.Created = time.Now().Unix()
	return d.CacheMetadata.SaveCache(d.GetPoolType(), cache.ID, cache)
}

func (d *DefaultEnclavePool) ListCache(lastCacheID string, limit int32) ([]*v1alpha1.Cache, error) {
	return d.CacheMetadata.ListCache(d.GetPoolType(), lastCacheID, limit)
}

func (d *DefaultEnclavePool) DeleteCache(ID string) error {
	cache, err := d.GetCache(ID)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(cache.SavePath); err != nil {
		return err
	}
	return d.CacheMetadata.DeleteCache(d.GetPoolType(), ID)
}

func (d *DefaultEnclavePool) LoadCache(ID, targetPath string) error {
	cache, err := d.GetCache(ID)
	if err != nil {
		return err
	}
	if _, err := os.Stat(targetPath); err != nil {
		return fmt.Errorf("target path is not exist. error: %++v", err)
	}
	if _, err := utils.ExecCmd("/bin/cp", []string{"-fr", fmt.Sprintf("%s/", cache.SavePath), targetPath}); err != nil {
		return err
	}
	return nil
}

func (d *DefaultEnclavePool) GetPoolType() string {
	return "default"
}

func (d *DefaultEnclavePool) BuildCacheSavePath(rootDir string, cache *v1alpha1.Cache) (string, error) {
	caches, err := d.CacheMetadata.GetAncestorCaches(cache)
	if err != nil {
		return "", err
	}
	paths := []string{rootDir}
	for index := len(caches) - 1; index >= 0; index-- {
		cache := caches[index]
		str := fmt.Sprintf("%s/%s", cache.Type, cache.ID)
		paths = append(paths, str)
	}
	paths = append(paths, "current")
	return strings.Join(paths, "/"), nil
}
