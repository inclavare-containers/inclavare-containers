package app

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/inclavare-containers/epm/cmd/epm/app/options"
	"github.com/inclavare-containers/epm/config"
	"github.com/inclavare-containers/epm/pkg/epm"
	"github.com/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/inclavare-containers/epm/pkg/epm/bundle-cache-pool/occlum"
	"github.com/inclavare-containers/epm/pkg/epm/enclave-cache-pool/enclavepool"
	cache_metadata "github.com/inclavare-containers/epm/pkg/metadata"
	"github.com/golang/glog"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

func runServer(opts *options.Options, stopCh <-chan struct{}) error {
	var err error
	var cfg config.Config

	if err = opts.ApplyTo(&cfg); err != nil {
		return err
	}

	// setting the grpc options
	serverOpts := []grpc.ServerOption{
		grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	}
	if cfg.GRPC.MaxRecvMsgSize > 0 {
		serverOpts = append(serverOpts, grpc.MaxRecvMsgSize(cfg.GRPC.MaxRecvMsgSize))
	}
	if cfg.GRPC.MaxSendMsgSize > 0 {
		serverOpts = append(serverOpts, grpc.MaxSendMsgSize(cfg.GRPC.MaxSendMsgSize))
	}
	metadata, err := cache_metadata.NewMetadataServer(cfg.DBPath, time.Second*time.Duration(cfg.DBTimeout))

	if err != nil {
		return fmt.Errorf("create metadata server failed. %++v", err)
	}
	defer metadata.Close()

	server := epm.EnclavePoolManagerServer{}

	bundleCache0 := occlum.NewBundleCache0Manager(cfg.Root, metadata)
	bundleCache1 := occlum.NewBundleCache1Manager(cfg.Root, metadata)
	bundleCache2 := occlum.NewBundleCache2Manager(cfg.Root, metadata)

	// register the bundle cache pool managers to the manager server
	server.RegisterCachePoolManager(bundleCache0)
	server.RegisterCachePoolManager(bundleCache1)
	server.RegisterCachePoolManager(bundleCache2)

	enclmanager := enclavepool.NewEnclaveCacheManager(cfg.Root)
	// register process cache pool manager to the manager server
	server.RegisterCachePoolManager(enclmanager)

	// start the grpc server with the server options
	s := grpc.NewServer(serverOpts...)
	// registry and start the cache pool manager server
	v1alpha1.RegisterEnclavePoolManagerServer(s, &server)
	// listen and serve
	if err := os.MkdirAll(filepath.Dir(cfg.GRPC.Address), 0755); err != nil {
		return err
	}
	if err := unix.Unlink(cfg.GRPC.Address); err != nil && !os.IsNotExist(err) {
		return err
	}
	lis, err := net.Listen("unix", cfg.GRPC.Address)
	if err != nil {
		return err
	}
	glog.Info("start the epm server...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to start epm server: %v", err)
	}
	<-stopCh

	return nil
}
