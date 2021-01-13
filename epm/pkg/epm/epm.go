package epm

import (
	"context"
	"fmt"

	"github.com/golang/glog"
	"github.com/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// EnclavePoolManagerServer represents the service that manages the enclave pools
type EnclavePoolManagerServer struct {
	// cachePools containers the mapping of the cache type and enclave pool
	cachePools map[string]EnclavePool
}

// GetCache gets the specified cache metadata
func (s *EnclavePoolManagerServer) GetCache(ctx context.Context, req *v1alpha1.GetCacheRequest) (*v1alpha1.GetCacheResponse, error) {
	manager, err := s.getCachePoolManager(req.Type)
	if err != nil {
		glog.Errorf("cache pool type %s is not found. error: %++v", req.Type, err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	cache, err := manager.GetCache(req.ID, req.SubType)
	if err != nil {
		glog.Errorf("get cache failed. request: %++v, error: %++v", req, err)
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	glog.Infof("get cache successfully. request: %++v", req)
	return &v1alpha1.GetCacheResponse{Cache: cache}, nil
}

func (s *EnclavePoolManagerServer) PickCache(ctx context.Context, req *v1alpha1.PickCacheRequest) (*v1alpha1.PickCacheResponse, error) {
	manager, err := s.getCachePoolManager(req.Type)
	if err != nil {
		glog.Errorf("cache pool type %s is not found. error: %++v", req.Type, err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	caches, err := manager.PickCache(req.SubType, req.Filters)
	if err != nil {
		glog.Errorf("pick caches failed. request: %++v, error: %++v", req, err)
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	glog.Infof("pick caches successfully. request: %++v", req)
	return &v1alpha1.PickCacheResponse{Caches: caches}, nil
}

// SaveCache saves the data to a cache directory and record the cache metadata
func (s *EnclavePoolManagerServer) SaveCache(ctx context.Context, req *v1alpha1.SaveCacheRequest) (*v1alpha1.SaveCacheResponse, error) {
	cache := req.Cache
	manager, err := s.getCachePoolManager(cache.Type)
	if err != nil {
		glog.Errorf("cache pool type %s is not found. error: %++v", cache.Type, err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	if err := manager.SaveCache(req.SourcePath, cache); err != nil {
		glog.Errorf("save cache failed. request: %++v, error: %++v", req, err)
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	glog.Infof("save cache successfully. request: %++v", req)
	return &v1alpha1.SaveCacheResponse{Ok: true}, nil
}

// SaveCache saves the data to a cache directory and record the cache metadata
func (s *EnclavePoolManagerServer) SaveFinalCache(ctx context.Context, req *v1alpha1.SaveCacheRequest) (*v1alpha1.SaveCacheResponse, error) {
	cache := req.Cache
	manager, err := s.getCachePoolManager(cache.Type)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	if err := manager.SaveFinalCache(cache.ID, cache.SubType); err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	return &v1alpha1.SaveCacheResponse{Ok: true}, nil
}

// ListCache lists part of or all of the cache metadata
func (s *EnclavePoolManagerServer) ListCache(ctx context.Context, req *v1alpha1.ListCacheRequest) (*v1alpha1.ListCacheResponse, error) {
	manager, err := s.getCachePoolManager(req.Type)
	if err != nil {
		glog.Errorf("cache pool type %s is not found. error: %++v", req.Type, err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	caches, err := manager.ListCache(req.LastCacheID, req.SubType, req.Limit)
	if err != nil {
		glog.Errorf("list cache failed. error: %++v", err)
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	glog.Infof("list caches successfully. request: %++v", req)
	return &v1alpha1.ListCacheResponse{Caches: caches}, nil
}

// DeleteCache deletes the specified cached data and remove the corresponding cache metadata
func (s *EnclavePoolManagerServer) DeleteCache(ctx context.Context, req *v1alpha1.DeleteCacheRequest) (*v1alpha1.DeleteCacheResponse, error) {
	manager, err := s.getCachePoolManager(req.Type)
	if err != nil {
		glog.Errorf("cache pool type %s is not found. error: %++v", req.Type, err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	if err := manager.DeleteCache(req.ID, req.SubType); err != nil {
		glog.Errorf("delete cache failed. request: %++v, error: %++v", req, err)
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	glog.Infof("delete cache successfully. request: %++v", req)
	return &v1alpha1.DeleteCacheResponse{Ok: true}, nil
}

// LoadCache loads the specified cache data to work directory
func (s *EnclavePoolManagerServer) LoadCache(ctx context.Context, req *v1alpha1.LoadCacheRequest) (*v1alpha1.LoadCacheResponse, error) {
	manager, err := s.getCachePoolManager(req.Type)
	if err != nil {
		glog.Errorf("cache pool type %s is not found. error: %++v", req.Type, err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	if err := manager.LoadCache(req.ID, req.SubType, req.TargetPath); err != nil {
		glog.Errorf("load cache failed. request: %++v, error: %++v", req, err)
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	glog.Infof("load cache successfully. request: %++v", req)
	return &v1alpha1.LoadCacheResponse{Ok: true}, nil
}

// Healthz represents epm service's running state
func (s *EnclavePoolManagerServer) Healthz(ctx context.Context, req *v1alpha1.HealthzRequest) (*v1alpha1.HealthzResponse, error) {
	manager, err := s.getCachePoolManager(req.Type)
	if err != nil {
		glog.Errorf("cache pool type %s is not found. error: %++v", req.Type, err)
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	if !manager.Healthz() {
		glog.Errorf("health check failed!")
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	glog.Infof("health check successfully!")
	return &v1alpha1.HealthzResponse{Ok: true}, nil
}

// RegisterCachePoolManager register the cache pool manager to the cache pool manager server
func (s *EnclavePoolManagerServer) RegisterCachePoolManager(m EnclavePool) {
	if s.cachePools == nil {
		s.cachePools = make(map[string]EnclavePool)
	}
	s.cachePools[m.GetPoolType()] = m
}

// getCachePoolManager gets the cache pool manager by the cache type
func (s *EnclavePoolManagerServer) getCachePoolManager(cacheType string) (EnclavePool, error) {
	manager, ok := s.cachePools[cacheType]
	if ok && manager != nil {
		return manager, nil
	}
	return nil, fmt.Errorf("cachePoolManager is not found. cacheType: %s", cacheType)
}
