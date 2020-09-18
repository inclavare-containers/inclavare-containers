package occlum

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alibaba/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/alibaba/inclavare-containers/epm/pkg/epm/bundle-cache-pool/occlum/constants"
	"github.com/alibaba/inclavare-containers/epm/pkg/epm/bundle-cache-pool/occlum/types"
	cache_metadata "github.com/alibaba/inclavare-containers/epm/pkg/metadata"
	"github.com/stretchr/testify/assert"
)

func Test_BundleCach0Manager_SaveCache(t *testing.T) {
	metadata, err := cache_metadata.NewMetadataServer("/tmp/test/test.db", time.Second*5)
	assert.Nil(t, err)
	ID := "001"
	m := NewBundleCach0Manager("/tmp/test/epm", metadata)
	sourcePath := "/tmp/test/src/rune"
	cache := &v1alpha1.Cache{
		Type:   string(types.BundleCache0PoolType),
		Parent: nil,
		ID:     ID,
	}
	err = m.SaveCache(sourcePath, cache)
	assert.Nil(t, err)
	cache, err = m.CacheMetadata.GetCache(string(types.BundleCache0PoolType), ID)
	assert.Nil(t, err)
	fmt.Printf("cache:= %++v", cache)
	b, err := ioutil.ReadFile(filepath.Join(m.Root, cache.Type, cache.ID, "current", constants.OcclumStatusFileName))
	assert.Nil(t, err)
	assert.Equal(t, "image built", string(b))
	b, err = ioutil.ReadFile(filepath.Join(m.Root, cache.Type, cache.ID, "current", constants.OcclumSGXModeFileName))
	assert.Nil(t, err)
	assert.Equal(t, "HW", string(b))
}

func Test_BundleCach1Manager_SaveCache(t *testing.T) {
	metadata, err := cache_metadata.NewMetadataServer("/tmp/test/test.db", time.Second*5)
	assert.Nil(t, err)
	ID := "x001"
	m := NewBundleCach1Manager("/tmp/test/epm", metadata)
	sourcePath := "/tmp/test/src/rune"
	parent := &v1alpha1.Cache{
		Type:   string(types.BundleCache0PoolType),
		Parent: nil,
		ID:     "001",
	}
	cache := &v1alpha1.Cache{
		Type:   string(types.BundleCache1PoolType),
		Parent: parent,
		ID:     ID,
	}
	err = m.CacheMetadata.SaveCache(parent.Type, parent.ID, parent)
	assert.Nil(t, err)
	err = m.SaveCache(sourcePath, cache)
	if err != nil {
		fmt.Printf("%++v", err)
		t.Fatal(err)
	}
	assert.Nil(t, err)
	cache, err = m.CacheMetadata.GetCache(string(types.BundleCache1PoolType), ID)
	assert.Nil(t, err)
	fmt.Printf("cache:= %++v", cache)
	b, err := ioutil.ReadFile(filepath.Join(m.Root, parent.Type, parent.ID, cache.Type, cache.ID, "current", constants.OcclumStatusFileName))
	assert.Nil(t, err)
	assert.Equal(t, "built", string(b))
}

func Test_BundleCach2Manager_SaveCache(t *testing.T) {
	metadata, err := cache_metadata.NewMetadataServer("/tmp/test/test.db", time.Second*5)
	assert.Nil(t, err)
	ID := "xxx001"
	m := NewBundleCach2Manager("/tmp/test/epm", metadata)
	sourcePath := "/tmp/test/src/rune"
	ancestor := &v1alpha1.Cache{
		Type:   string(types.BundleCache0PoolType),
		Parent: nil,
		ID:     "001",
	}
	parent := &v1alpha1.Cache{
		Type:   string(types.BundleCache1PoolType),
		Parent: ancestor,
		ID:     "x001",
	}
	cache := &v1alpha1.Cache{
		Type:   string(types.BundleCache2PoolType),
		Parent: parent,
		ID:     ID,
	}
	err = m.CacheMetadata.SaveCache(ancestor.Type, ancestor.ID, ancestor)
	assert.Nil(t, err)
	err = m.CacheMetadata.SaveCache(parent.Type, parent.ID, parent)
	assert.Nil(t, err)
	err = m.SaveCache(sourcePath, cache)
	assert.Nil(t, err)
	cache, err = m.CacheMetadata.GetCache(string(types.BundleCache2PoolType), ID)
	assert.Nil(t, err)
	fmt.Printf("cache:= %++v", cache)
	_, err = os.Stat(filepath.Join(m.Root, ancestor.Type, ancestor.ID, parent.Type, parent.ID,
		cache.Type, cache.ID, "current", "build/lib/libocclum-libos.signed.so"))
	assert.Nil(t, err)
}

func Test_LoadBundleCache0(t *testing.T) {
	metadata, err := cache_metadata.NewMetadataServer("/tmp/test/test.db", time.Second*5)
	assert.Nil(t, err)
	ID := "001"
	sourcePath := "/tmp/test/src/rune"
	m := NewBundleCach0Manager("/tmp/test/epm", metadata)
	cache := &v1alpha1.Cache{
		Type:   string(types.BundleCache0PoolType),
		Parent: nil,
		ID:     ID,
	}
	err = m.SaveCache(sourcePath, cache)
	assert.Nil(t, err)

	cache, err = m.GetCache(ID)
	//cache, err = m.CacheMetadata.GetCache(string(types.BundleCache0PoolType), ID)
	assert.Nil(t, err)
	fmt.Printf("cache:= %++v", cache)

	targetPath := "/tmp/test/dst/rune"
	os.RemoveAll(targetPath)
	os.MkdirAll(targetPath, 0755)
	err = m.LoadCache(ID, targetPath)
	assert.Nil(t, err)

	b, err := ioutil.ReadFile(filepath.Join(targetPath, constants.OcclumStatusFileName))
	assert.Nil(t, err)
	assert.Equal(t, "image built", string(b))
	b, err = ioutil.ReadFile(filepath.Join(targetPath, constants.OcclumSGXModeFileName))
	assert.Nil(t, err)
	assert.Equal(t, "HW", string(b))
}

func Test_LoadCacheAll(t *testing.T) {
	metadata, err := cache_metadata.NewMetadataServer("/tmp/test/test.db", time.Second*5)
	assert.Nil(t, err)
	sourcePath := "/tmp/test/src/rune"
	root := "/tmp/test/epm"
	m0ID := "001"
	m0 := NewBundleCach0Manager(root, metadata)
	m0Cache := &v1alpha1.Cache{
		Type:   m0.Type,
		Parent: nil,
		ID:     m0ID,
	}
	err = m0.SaveCache(sourcePath, m0Cache)
	assert.Nil(t, err)

	m0Cache, err = m0.GetCache(m0ID)
	assert.Nil(t, err)

	m1ID := "x001"
	m1 := NewBundleCach1Manager(root, metadata)
	m1Cache := &v1alpha1.Cache{
		Type:   m1.Type,
		Parent: nil,
		ID:     m1ID,
	}
	err = m1.SaveCache(sourcePath, m1Cache)
	assert.Nil(t, err)

	m1Cache, err = m1.GetCache(m1ID)
	assert.Nil(t, err)

	m2ID := "xxx001"
	m2 := NewBundleCach2Manager(root, metadata)
	m2Cache := &v1alpha1.Cache{
		Type:   m2.Type,
		Parent: nil,
		ID:     m2ID,
	}
	err = m2.SaveCache(sourcePath, m2Cache)
	assert.Nil(t, err)

	m2Cache, err = m2.GetCache(m2ID)
	assert.Nil(t, err)

	targetPath := "/tmp/test/dst/rune"
	os.RemoveAll(targetPath)
	os.MkdirAll(targetPath, 0755)
	err = m0.LoadCache(m0ID, targetPath)
	assert.Nil(t, err)
	err = m1.LoadCache(m1ID, targetPath)
	assert.Nil(t, err)
	err = m2.LoadCache(m2ID, targetPath)
	assert.Nil(t, err)

	b, err := ioutil.ReadFile(filepath.Join(targetPath, constants.OcclumStatusFileName))
	assert.Nil(t, err)
	assert.Equal(t, "built", string(b))
	b, err = ioutil.ReadFile(filepath.Join(targetPath, constants.OcclumSGXModeFileName))
	assert.Nil(t, err)
	assert.Equal(t, "HW", string(b))
}
