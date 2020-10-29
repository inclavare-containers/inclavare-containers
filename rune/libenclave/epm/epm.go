package epm

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/alibaba/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/fsnotify/fsnotify"
	"github.com/golang/protobuf/ptypes"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	address = "/var/run/containerd/containerd.sock"
)

func UnixConnect(addr string, t time.Duration) (net.Conn, error) {
	unix_addr, err := net.ResolveUnixAddr("unix", address)
	conn, err := net.DialUnix("unix", nil, unix_addr)
	return conn, err
}

func GetEnclave() *v1alpha1.Enclave {
	ID := CreateRand()
	return GetCache(ID)
}
func GetCache(ID string) *v1alpha1.Enclave {
	var fd int = 0
	var enclaveinfo v1alpha1.Enclave

	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithDialer(UnixConnect))
	if err != nil {
		logrus.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := v1alpha1.NewEnclavePoolManagerClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	sockpath := "/var/run/sock/" + ID
	go recvFd(sockpath, &fd)

	Type := "enclave-cache-pool"
	cacheResp, err := c.GetCache(ctx, &v1alpha1.GetCacheRequest{Type: Type, ID: ID})
	if err != nil {
		logrus.Fatalf("could not get cache from enclave cache pool: %v", err)
	}
	if cacheResp.Cache == nil {
		syscall.Unlink(sockpath)
		logrus.Infof("There is no enclave in cache pool")
		return nil
	}
	ptypes.UnmarshalAny(cacheResp.Cache.Options, &enclaveinfo)
	enclaveinfo.Fd = int64(fd)
	return &enclaveinfo
}

func SavePreCache() string {
	ID := CreateRand()
	SaveCache(ID)
	return ID
}

func SaveCache(ID string) {
	var cache v1alpha1.Cache

	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithDialer(UnixConnect))
	if err != nil {
		logrus.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := v1alpha1.NewEnclavePoolManagerClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	enclaveinfo := &v1alpha1.Enclave{}
	enclaveinfo = GetParseMaps(os.Getpid())

	unisock := "/var/run/sock/" + ID

	watcher, err := fsnotify.NewWatcher()
	defer watcher.Close()
	if err != nil {
		logrus.Fatal(err)
	}

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if (event.Op&fsnotify.Create == fsnotify.Create) && (event.Name == unisock) {
					close(done)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logrus.Infof("error:", err)
			}
		}
	}()

	err = watcher.Add("/var/run/sock/")
	if err != nil {
		logrus.Fatal(err)
	}

	cache.Options, err = ptypes.MarshalAny(enclaveinfo)
	if err != nil {
		logrus.Fatalf("Marshal encalveinfo failure: %v", err)
	}

	cache.ID = ID
	cache.Type = "enclave-cache-pool"

	c.SaveCache(ctx, &v1alpha1.SaveCacheRequest{Cache: &cache})

	<-done
	sendFd(unisock, int(enclaveinfo.Fd))
}

func SaveEnclave(ID string) {
	var cache v1alpha1.Cache

	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithDialer(UnixConnect))
	if err != nil {
		logrus.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := v1alpha1.NewEnclavePoolManagerClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	cache.Type = "enclave-cache-pool"
	cache.ID = ID
	c.SaveFinalCache(ctx, &v1alpha1.SaveCacheRequest{Cache: &cache})
}

func CreateRand() string {
	return fmt.Sprintf("%06v", rand.New(rand.NewSource(time.Now().UnixNano())).Int31n(1000000))
}
