package epm

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var epmchan = make(chan error, 1)

const (
	InvalidEpmID string = "InvalidEPMID"
	address             = "/var/run/epm/epm.sock"
	sockpathdir         = "/var/run/epm"
)

func UnixConnect(addr string, t time.Duration) (net.Conn, error) {
	unix_addr, err := net.ResolveUnixAddr("unix", address)
	conn, err := net.DialUnix("unix", nil, unix_addr)
	return conn, err
}

func GetEnclave(subtype string) *v1alpha1.Enclave {
	ID := CreateRand()
	return GetCache(ID, subtype)
}

func GetCache(ID string, subtype string) *v1alpha1.Enclave {
	var fd int = 0
	var enclaveinfo v1alpha1.Enclave
	Type := "enclave-cache-pool"

	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithDialer(UnixConnect))
	if err != nil {
		logrus.Warnf("Fail to connect: %v", err)
	}
	defer conn.Close()
	c := v1alpha1.NewEnclavePoolManagerClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	healthzResp, err := c.Healthz(ctx, &v1alpha1.HealthzRequest{Type: Type})
	if err != nil {
		return nil
	}
	if !healthzResp.Ok {
		logrus.Warnf("EPM service is not in good running state!")
		return nil
	}

	sockpath := filepath.Join(sockpathdir, ID)
	go recvFd(sockpath, &fd)

	cacheResp, err := c.GetCache(ctx, &v1alpha1.GetCacheRequest{Type: Type, SubType: subtype, ID: ID})
	if err != nil {
		return nil
	}
	if cacheResp.Cache == nil {
	       /* FIXME: If enclave cache pool is empty, there is no SendFd from epm service. The goroutine recvFd
		* above will be suspended on accept, sockpath will not be unlinked. Here is unlinked manually.
		*/
		syscall.Unlink(sockpath)
		logrus.Infof("There is no enclave in cache pool")
		return nil
	}
	ptypes.UnmarshalAny(cacheResp.Cache.Options, &enclaveinfo)
	<-epmchan
	close(epmchan)
	enclaveinfo.Fd = int64(fd)
	return &enclaveinfo
}

func SavePreCache(subtype string, enclaveinfo *v1alpha1.Enclave) string {
	ID := CreateRand()
	err := SaveCache(ID, subtype, enclaveinfo)
	if err != nil {
		return InvalidEpmID
	}

	return ID
}

func SaveCache(ID string, subtype string, enclaveinfo *v1alpha1.Enclave) error {
	var cache v1alpha1.Cache
	Type := "enclave-cache-pool"

	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithDialer(UnixConnect))
	if err != nil {
		logrus.Warnf("Fail to connect: %v", err)
	}
	defer conn.Close()
	c := v1alpha1.NewEnclavePoolManagerClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	healthzResp, err := c.Healthz(ctx, &v1alpha1.HealthzRequest{Type: Type})
	if err != nil {
		return nil
	}
	if !healthzResp.Ok {
		logrus.Warnf("EPM service is not in good running state!")
		return nil
	}

	if enclaveinfo == nil {
		enclaveinfo = GetParseMaps(os.Getpid())
	}

	cache.Options, err = ptypes.MarshalAny(enclaveinfo)
	if err != nil {
		logrus.Fatalf("Marshal enclaveinfo failure: %v", err)
	}

	cache.ID = ID
	cache.Type = Type
	cache.SubType = subtype

	_, err = c.SaveCache(ctx, &v1alpha1.SaveCacheRequest{Cache: &cache})
	if err != nil {
		return err
	}

	unisock := filepath.Join(sockpathdir, ID)
	err = sendFd(unisock, int(enclaveinfo.Fd))
	if err != nil {
		return err
	}

	return nil
}

func SaveEnclave(ID string, subtype string) {
	var cache v1alpha1.Cache

	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithDialer(UnixConnect))
	if err != nil {
		logrus.Warnf("Fail to connect: %v", err)
	}
	defer conn.Close()
	c := v1alpha1.NewEnclavePoolManagerClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	cache.Type = "enclave-cache-pool"
	cache.ID = ID
	cache.SubType = subtype
	c.SaveFinalCache(ctx, &v1alpha1.SaveCacheRequest{Cache: &cache})
}

func CreateRand() string {
	return fmt.Sprintf("%06v", rand.New(rand.NewSource(time.Now().UnixNano())).Int31n(1000000))
}
