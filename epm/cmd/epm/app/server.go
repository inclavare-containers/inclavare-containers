package app

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/golang/glog"

	"github.com/alibaba/inclavare-containers/epm/cmd/epm/app/options"
	"github.com/alibaba/inclavare-containers/epm/config"
	"github.com/alibaba/inclavare-containers/epm/pkg/epm"
	"github.com/alibaba/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/alibaba/inclavare-containers/epm/pkg/epm/bundle-cache-pool/occlum"
	"github.com/alibaba/inclavare-containers/epm/pkg/epm/enclave-cache-pool/enclavepool"
	cache_metadata "github.com/alibaba/inclavare-containers/epm/pkg/metadata"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
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

	bundleCache0 := occlum.NewBundleCach0Manager(cfg.Root, metadata)
	bundleCache1 := occlum.NewBundleCach1Manager(cfg.Root, metadata)
	bundleCache2 := occlum.NewBundleCach2Manager(cfg.Root, metadata)

	// register the bundle cache pool managers to the manager server
	server.RegisterCachePoolManager(bundleCache0)
	server.RegisterCachePoolManager(bundleCache1)
	server.RegisterCachePoolManager(bundleCache2)

	enclmanager := enclavepool.NewEnclaveCacheManager(cfg.Root)
	enclmanager1 := enclavepool.NewEnclaveCacheOcclumManager(cfg.Root)
	// register process cache pool manager to the manager server
	server.RegisterCachePoolManager(enclmanager)
	server.RegisterCachePoolManager(enclmanager1)

	// start the grpc server with the server options
	s := grpc.NewServer(serverOpts...)
	// registry and start the cache pool manager server
	v1alpha1.RegisterEnclavePoolManagerServer(s, &server)
	// listen and serve
	lis, err := net.Listen("unix", cfg.GRPC.Address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	glog.Info("start the and epm server...")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to start epm server: %v", err)
	}
	<-stopCh
	return nil
}
