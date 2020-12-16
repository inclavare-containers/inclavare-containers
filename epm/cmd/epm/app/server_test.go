package app

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/inclavare-containers/epm/pkg/epm/bundle-cache-pool/occlum/types"
	"google.golang.org/grpc"
)

func Test_BundleGetCache0Manager(t *testing.T) {
	address := "unix:///tmp/var/run/epm/epm.sock"
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := v1alpha1.NewEnclavePoolManagerClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.GetCache(ctx, &v1alpha1.GetCacheRequest{
		Type: string(types.BundleCache0PoolType),
		ID:   "001",
	})
	if err != nil {
		log.Fatalf("could not get cache: %v", err)
	}
	log.Printf("Get cache: %v", r.GetCache())
}

func Test_BundleSaveCache0Manager(t *testing.T) {
	address := "unix:///tmp/var/run/epm/epm.sock"
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := v1alpha1.NewEnclavePoolManagerClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.SaveCache(ctx, &v1alpha1.SaveCacheRequest{
		Cache: &v1alpha1.Cache{
			Type: string(types.BundleCache0PoolType),
			ID:   "001",
		},
		SourcePath: "/tmp/src",
	})
	if err != nil {
		log.Fatalf("could not get cache: %v", err)
	}
	log.Printf("Get cache: %v", r.Ok)
}
