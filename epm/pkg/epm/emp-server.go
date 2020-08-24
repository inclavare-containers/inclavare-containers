package epm

import (
	"context"
	"fmt"

	"github.com/alibaba/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CachePoolManagerServer represents the service that manages the cache pool managers
type CachePoolManagerServer struct {
	v1alpha1.UnimplementedCachePoolManagerServer
	// cachePoolManagers containers the mapping of the cache type and cache pool manager
	cachePoolManagers map[string]CachePoolManager
}

// GetCache gets the specified cache metadata
func (s *CachePoolManagerServer) GetCache(ctx context.Context, req *v1alpha1.GetCacheRequest) (*v1alpha1.GetCacheResponse, error) {
	manager, err := s.getCachePoolManager(req.Type)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	cache, err := manager.GetCache(req.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	return &v1alpha1.GetCacheResponse{Cache: cache}, nil
}

// SaveCache saves the data to a cache directory and record the cache metadata
func (s *CachePoolManagerServer) SaveCache(ctx context.Context, req *v1alpha1.SaveCacheRequest) (*v1alpha1.SaveCacheResponse, error) {
	cache := req.Cache
	manager, err := s.getCachePoolManager(cache.Type)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	if err := manager.SaveCache(req.SourcePath, cache); err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	return &v1alpha1.SaveCacheResponse{Ok: true}, nil
}

// ListCache lists part of or all of the cache metadata
func (s *CachePoolManagerServer) ListCache(ctx context.Context, req *v1alpha1.ListCacheRequest) (*v1alpha1.ListCacheResponse, error) {
	manager, err := s.getCachePoolManager(req.Type)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	caches, err := manager.ListCache(req.LastCacheID, req.Limit)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	return &v1alpha1.ListCacheResponse{Caches: caches}, nil
}

// DeleteCache deletes the specified cached data and remove the corresponding cache metadata
func (s *CachePoolManagerServer) DeleteCache(ctx context.Context, req *v1alpha1.DeleteCacheRequest) (*v1alpha1.DeleteCacheResponse, error) {
	manager, err := s.getCachePoolManager(req.Type)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	if err := manager.DeleteCache(req.ID); err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	return &v1alpha1.DeleteCacheResponse{Ok: true}, nil
}

// LoadCache loads the specified cache data to work directory
func (s *CachePoolManagerServer) LoadCache(ctx context.Context, req *v1alpha1.LoadCacheRequest) (*v1alpha1.LoadCacheResponse, error) {
	manager, err := s.getCachePoolManager(req.Type)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}
	if err := manager.LoadCache(req.ID, req.TargetPath); err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	return &v1alpha1.LoadCacheResponse{Ok: true}, nil
}

// RegistryCachePoolManager registry the cache pool manager to the cache pool manager server
func (s *CachePoolManagerServer) RegistryCachePoolManager(m CachePoolManager) {
	if s.cachePoolManagers == nil {
		s.cachePoolManagers = make(map[string]CachePoolManager)
	}
	s.cachePoolManagers[m.GetCacheType()] = m
}

// getCachePoolManager gets the cache pool manager by the cache type
func (s *CachePoolManagerServer) getCachePoolManager(cacheType string) (CachePoolManager, error) {
	manager, ok := s.cachePoolManagers[cacheType]
	if ok && manager != nil {
		return manager, nil
	}
	return nil, fmt.Errorf("cachePoolManager is not found. cacheType: %s", cacheType)
}
