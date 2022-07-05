package v2

import (
	"context"

	"github.com/confidential-containers/enclave-cc/shim/runtime/v2/rune/image"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/runtime/v2/shim"
	"github.com/containerd/containerd/runtime/v2/task"
	"github.com/containerd/ttrpc"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func init() {
	plugin.Register(&plugin.Registration{
		Type:     plugin.TTRPCPlugin,
		ID:       "image",
		Requires: []plugin.Type{"*"},
		InitFn:   initImageService,
	})
}

type ImageService struct {
	s *service
}

func initImageService(ic *plugin.InitContext) (interface{}, error) {
	i, err := ic.GetByID(plugin.TTRPCPlugin, "task")
	if err != nil {
		return nil, errors.Errorf("get task plugin error. %v", err)
	}
	task := i.(shim.TaskService)
	s := task.TaskService.(*service)
	is := &ImageService{s: s}
	return is, nil
}

func (is *ImageService) RegisterTTRPC(server *ttrpc.Server) error {
	task.RegisterImageService(server, is)
	return nil
}

// PullImage and unbundle ready for container creation
func (is *ImageService) PullImage(ctx context.Context, req *task.PullImageRequest) (_ *task.PullImageResponse, err error) {
	is.s.mu.Lock()
	defer is.s.mu.Unlock()

	shimLog.WithFields(logrus.Fields{
		"image": req.Image,
	}).Debug("Making image pull request")

	r := &image.PullImageReq{
		Image: req.Image,
	}

	resp, err := is.s.agent.PullImage(ctx, r)
	if err != nil {
		shimLog.Errorf("rune runtime PullImage err. %v", err)
		return nil, err
	}

	return &task.PullImageResponse{
		ImageRef: resp.ImageRef,
	}, err
}
