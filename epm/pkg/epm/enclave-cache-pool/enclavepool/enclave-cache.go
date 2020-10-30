package enclavepool

import (
	"sync"
	"syscall"

	cache_manager "github.com/alibaba/inclavare-containers/epm/pkg/epm"
	"github.com/alibaba/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/alibaba/inclavare-containers/epm/pkg/epm/enclave-cache-pool/types"
	"github.com/alibaba/inclavare-containers/epm/pkg/utils"
	"github.com/golang/protobuf/ptypes"
	"github.com/sirupsen/logrus"
)

var mut sync.Mutex
var EnclavePoolStore map[int]*v1alpha1.Enclave
var EnclavePoolPreStore map[string]*v1alpha1.Enclave

// EnclaveCacheManager declared as process pool management.
type EnclaveCacheManager struct {
	cache_manager.DefaultEnclavePool
}

// NewEnclaveCacheManager is used to define an EnclaveCacheManager.
func NewEnclaveCacheManager(root string) *EnclaveCacheManager {
	InitEnclavePool()
	return &EnclaveCacheManager{
		DefaultEnclavePool: cache_manager.DefaultEnclavePool{
			Root:        root,
			Type:        string(types.EnclavePoolType),
			Enclaveinfo: EnclavePoolStore,
		}}
}

func InitEnclavePool() {
	EnclavePoolPreStore = make(map[string]*v1alpha1.Enclave)
	EnclavePoolStore = make(map[int]*v1alpha1.Enclave)
}

func (d *EnclaveCacheManager) PreStoreEnclave(enclaveinfo v1alpha1.Enclave, ID string) {
	mut.Lock()
	defer mut.Unlock()
	EnclavePoolPreStore[ID] = &enclaveinfo
}

func (d *EnclaveCacheManager) DeleteEnclave(nr int) {
	delete(EnclavePoolStore, nr)
}

func (d *EnclaveCacheManager) GetEnclave() *v1alpha1.Enclave {
	for _, v := range EnclavePoolStore {
		if v == nil {
			logrus.Infof("Enclave Pool is empty")
		}
		return v
	}
	return nil
}

// GetPoolType represents request pool type.
func (d *EnclaveCacheManager) GetPoolType() string {
	return d.Type
}

// SaveCache represents enclave info will be saved into EnclavePoolStore
func (d *EnclaveCacheManager) SaveCache(sourcePath string, cache *v1alpha1.Cache) error {
	var enclaveinfo v1alpha1.Enclave
	// Get the enclave file descriptor from rune.
	enclavefd, err := utils.RecvFd("/var/run/sock/" + cache.ID)
	if err != nil {
		return err
	}

	ptypes.UnmarshalAny(cache.Options, &enclaveinfo)
	enclaveinfo.Fd = int64(enclavefd)
	d.PreStoreEnclave(enclaveinfo, cache.ID)
	return err
}

// GetCache gets the cache by ID
func (d *EnclaveCacheManager) GetCache(ID string) (*v1alpha1.Cache, error) {
	var cache v1alpha1.Cache
	var err error

	mut.Lock()
	defer mut.Unlock()

	enclaveinfo := d.GetEnclave()
	if enclaveinfo == nil {
		return nil, nil
	}

	cache.ID = ID
	cache.Options, err = ptypes.MarshalAny(enclaveinfo)
	if err != nil {
		return nil, err
	}

	fd := enclaveinfo.Fd
	err = utils.SendFd("/var/run/sock/"+cache.ID, int(fd))
	if err != nil {
		logrus.Warnf("send fd to epm client failure!", err)
	}
	d.DeleteEnclave(int(fd))

	err = syscall.Close(int(fd))
	if err != nil {
		logrus.Warnf("Close enclave fd failure in GetCache!", err)
	}
	return &cache, err
}

func (d *EnclaveCacheManager) SaveFinalCache(ID string) error {
	var Enc *v1alpha1.Enclave
	mut.Lock()
	defer mut.Unlock()
	Enc = EnclavePoolPreStore[ID]
	EnclavePoolStore[int(Enc.Fd)] = EnclavePoolPreStore[ID]
	return nil
}
