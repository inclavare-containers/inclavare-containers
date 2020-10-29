package enclavepool

import (
	"fmt"
	"sync"
	"syscall"

	cache_manager "github.com/alibaba/inclavare-containers/epm/pkg/epm"
	"github.com/alibaba/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/alibaba/inclavare-containers/epm/pkg/epm/enclave-cache-pool/types"
	"github.com/alibaba/inclavare-containers/epm/pkg/utils"
	"github.com/golang/protobuf/ptypes"
)

var mut1 sync.Mutex
var EnclavePoolOcclumStore map[int]*v1alpha1.Enclave
var EnclavePoolOcclumPreStore map[string]*v1alpha1.Enclave

// EnclaveCacheOcclumManager declared as process pool management.
type EnclaveCacheOcclumManager struct {
	cache_manager.DefaultEnclavePool
}

// NewEnclaveCacheOcclumManager is used to define an EnclaveCacheOcclumManager.
func NewEnclaveCacheOcclumManager(root string) *EnclaveCacheOcclumManager {
	InitEnclavePoolOcclum()
	return &EnclaveCacheOcclumManager{
		DefaultEnclavePool: cache_manager.DefaultEnclavePool{
			Root:        root,
			Type:        string(types.EnclavePoolOcclumType),
			Enclaveinfo: EnclavePoolOcclumStore,
		}}
}

func InitEnclavePoolOcclum() {
	EnclavePoolOcclumPreStore = make(map[string]*v1alpha1.Enclave)
	EnclavePoolOcclumStore = make(map[int]*v1alpha1.Enclave)
}

func (d *EnclaveCacheOcclumManager) PreStoreEnclave(enclaveinfo v1alpha1.Enclave, ID string) {
	mut1.Lock()
	defer mut1.Unlock()
	EnclavePoolOcclumPreStore[ID] = &enclaveinfo
}

func (d *EnclaveCacheOcclumManager) DeleteEnclave(nr int) {
	delete(EnclavePoolOcclumStore, nr)
}

func (d *EnclaveCacheOcclumManager) GetEnclave() *v1alpha1.Enclave {
	for _, v := range EnclavePoolOcclumStore {
		if v == nil {
			fmt.Println("Enclave Pool is empty")
		}
		return v
	}
	return nil
}

// GetPoolType represents request pool type.
func (d *EnclaveCacheOcclumManager) GetPoolType() string {
	return d.Type
}

// SaveCache represents enclave info will be saved into EnclavePoolOcclumStore
func (d *EnclaveCacheOcclumManager) SaveCache(sourcePath string, cache *v1alpha1.Cache) error {
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
func (d *EnclaveCacheOcclumManager) GetCache(ID string) (*v1alpha1.Cache, error) {
	var cache v1alpha1.Cache
	var err error

	mut1.Lock()
	defer mut1.Unlock()

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
		fmt.Println("send fd to epm client failure!", err)
	}
	d.DeleteEnclave(int(fd))

	err = syscall.Close(int(fd))
	if err != nil {
		fmt.Println("Close enclave fd failure in GetCache!", err, fd)
	}
	return &cache, err
}

func (d *EnclaveCacheOcclumManager) SaveFinalCache(ID string) error {
	var Enc *v1alpha1.Enclave
	mut1.Lock()
	defer mut1.Unlock()
	Enc = EnclavePoolOcclumPreStore[ID]
	EnclavePoolOcclumStore[int(Enc.Fd)] = EnclavePoolOcclumPreStore[ID]
	return nil
}
