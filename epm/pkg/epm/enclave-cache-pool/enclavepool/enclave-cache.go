package enclavepool

import (
	"path/filepath"
	"sync"
	"syscall"

	"github.com/golang/protobuf/ptypes"
	cache_manager "github.com/inclavare-containers/epm/pkg/epm"
	"github.com/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/inclavare-containers/epm/pkg/epm/enclave-cache-pool/types"
	"github.com/inclavare-containers/epm/pkg/utils"
	"github.com/sirupsen/logrus"
)

const (
	EPMDir string = "/var/run/epm"
)

var mut sync.Mutex
var EnclavePoolStore map[string]map[int]*v1alpha1.Enclave
var EnclavePoolPreStore map[string]map[string]*v1alpha1.Enclave
var EnclavePoolTmpStore map[string]*v1alpha1.Enclave
var EnclavePoolTmpPreStore map[int]*v1alpha1.Enclave

// EnclaveCacheManager declared as enclave pool management.
type EnclaveCacheManager struct {
	cache_manager.DefaultEnclavePool
}

// NewEnclaveCacheManager is used to define an EnclaveCacheManager.
func NewEnclaveCacheManager(root string) *EnclaveCacheManager {
	InitEnclavePool()
	return &EnclaveCacheManager{
		DefaultEnclavePool: cache_manager.DefaultEnclavePool{
			Root: root,
			Type: string(types.EnclavePoolType),
		}}
}

func InitEnclavePool() {
	EnclavePoolPreStore = make(map[string]map[string]*v1alpha1.Enclave)
	EnclavePoolStore = make(map[string]map[int]*v1alpha1.Enclave)
	EnclavePoolTmpPreStore = make(map[int]*v1alpha1.Enclave)
	EnclavePoolTmpStore = make(map[string]*v1alpha1.Enclave)
}

func (d *EnclaveCacheManager) PreStoreEnclave(enclaveinfo v1alpha1.Enclave, ID string, subtype string) {
	mut.Lock()
	defer mut.Unlock()
	EnclavePoolTmpStore[ID] = &enclaveinfo
	EnclavePoolPreStore[subtype] = EnclavePoolTmpStore
}

func (d *EnclaveCacheManager) DeleteEnclave(nr int, subtype string) {
	delete(EnclavePoolStore[subtype], nr)
}

func (d *EnclaveCacheManager) GetEnclave(subtype string) *v1alpha1.Enclave {
	for _, v := range EnclavePoolStore[subtype] {
		return v
	}

	return nil
}

// GetPoolType represents request pool type.
func (d *EnclaveCacheManager) GetPoolType() string {
	return d.Type
}

func (d *EnclaveCacheManager) Healthz() bool {
	/* FIXME: If there are more states in epm service, please rich the interface */
	return true
}

func SaveFd(cacheID string, subtype string, err *error) {
	var fd int

	sockpath := filepath.Join(EPMDir, cacheID)
	fd, *err = utils.RecvFd(sockpath)
	if fd != -1 {
		EnclavePoolPreStore[subtype][cacheID].Fd = int64(fd)
	}
}

// SaveCache represents enclave info will be saved into EnclavePoolStore
func (d *EnclaveCacheManager) SaveCache(sourcePath string, cache *v1alpha1.Cache) error {
	var err error
	var enclaveinfo v1alpha1.Enclave

	go SaveFd(cache.ID, cache.SubType, &err)
	ptypes.UnmarshalAny(cache.Options, &enclaveinfo)
	d.PreStoreEnclave(enclaveinfo, cache.ID, cache.SubType)

	return err
}

// GetCache gets the cache by ID
func (d *EnclaveCacheManager) GetCache(ID string, subtype string) (*v1alpha1.Cache, error) {
	var cache v1alpha1.Cache
	var err error

	mut.Lock()
	defer mut.Unlock()

	enclaveinfo := d.GetEnclave(subtype)
	if enclaveinfo == nil {
		return nil, nil
	}

	cache.ID = ID
	cache.Options, err = ptypes.MarshalAny(enclaveinfo)
	if err != nil {
		return nil, err
	}

	fd := enclaveinfo.Fd
	sockpath := filepath.Join(EPMDir, cache.ID)
	err = utils.SendFd(sockpath, int(fd))
	if err != nil {
		logrus.Warnf("Send fd to epm client failure!", err)
	}
	d.DeleteEnclave(int(fd), subtype)

	err = syscall.Close(int(fd))
	if err != nil {
		logrus.Warnf("Close enclave fd failure in GetCache!", err)
	}
	return &cache, err
}

func (d *EnclaveCacheManager) SaveFinalCache(ID string, subtype string) error {
	var Enc *v1alpha1.Enclave
	mut.Lock()
	defer mut.Unlock()
	Enc = EnclavePoolPreStore[subtype][ID]
	EnclavePoolTmpPreStore[int(Enc.Fd)] = Enc
	EnclavePoolStore[subtype] = EnclavePoolTmpPreStore

	return nil
}
