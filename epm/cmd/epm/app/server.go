package app

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/alibaba/inclavare-containers/epm/cmd/epm/app/options"
	"github.com/alibaba/inclavare-containers/epm/config"
	"github.com/alibaba/inclavare-containers/epm/pkg/epm"
	"github.com/alibaba/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/alibaba/inclavare-containers/epm/pkg/epm/bundle-cache-pool/occlum"
	cache_metadata "github.com/alibaba/inclavare-containers/epm/pkg/metadata"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"google.golang.org/grpc"
)

func runServer(opts *options.Options) error {
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
	defer metadata.Close()

	if err != nil {
		return fmt.Errorf("create metadata server failed. %++v", err)
	}

	server := epm.CachePoolManagerServer{}

	bundleCache0 := occlum.Cach0Manager{
		DefaultCachePoolManager: epm.DefaultCachePoolManager{
			Root:          cfg.Root,
			CacheMetadata: metadata,
		}}
	bundleCache1 := occlum.Cach1Manager{
		DefaultCachePoolManager: epm.DefaultCachePoolManager{
			Root:          cfg.Root,
			CacheMetadata: metadata,
		}}
	bundleCache2 := occlum.Cach2Manager{
		DefaultCachePoolManager: epm.DefaultCachePoolManager{
			Root:          cfg.Root,
			CacheMetadata: metadata,
		}}
	// registry the bundle cache pool managers to the manager server
	server.RegistryCachePoolManager(&bundleCache0)
	server.RegistryCachePoolManager(&bundleCache1)
	server.RegistryCachePoolManager(&bundleCache2)

	// start the grpc server with the server options
	s := grpc.NewServer(serverOpts...)
	// registry and start the cache pool manager server
	v1alpha1.RegisterCachePoolManagerServer(s, &server)
	// listen and serve
	lis, err := net.Listen("udp", cfg.GRPC.Address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to start cache pool manager server: %v", err)
	}
	return nil
}
