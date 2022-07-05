package v2

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	shim_config "github.com/confidential-containers/enclave-cc/shim/config"
	agentClient "github.com/confidential-containers/enclave-cc/shim/runtime/v2/rune/agent/client"
	grpc "github.com/confidential-containers/enclave-cc/shim/runtime/v2/rune/agent/grpc"
	"github.com/confidential-containers/enclave-cc/shim/runtime/v2/rune/constants"
	"github.com/confidential-containers/enclave-cc/shim/runtime/v2/rune/image"
	types "github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/pkg/process"
	"github.com/containerd/containerd/runtime/v2/runc"
	taskAPI "github.com/containerd/containerd/runtime/v2/task"
	"github.com/containerd/continuity/fs"
	runcC "github.com/containerd/go-runc"
	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"
)

const (
	grpcPullImageRequest = "grpc.PullImageRequest"
)

var (
	defaultRequestTimeout = 60 * time.Second
)

type Agent struct {
	// ID of the container
	ID string
	// Bundle path
	Bundle string

	// lock protects the client pointer
	sync.Mutex

	reqHandlers map[string]reqFunc
	URL         string
	dialTimout  uint32
	keepConn    bool
	dead        bool
	client      *agentClient.AgentClient
}

func (c *Agent) Logger() *logrus.Entry {
	return logrus.WithField("source", "agent_enclave_container")
}

func (c *Agent) connect(ctx context.Context) error {
	if c.dead {
		return errors.New("Dead agent")
	}
	// lockless quick pass
	if c.client != nil {
		return nil
	}

	// This is for the first connection only, to prevent race
	c.Lock()
	defer c.Unlock()
	if c.client != nil {
		return nil
	}

	c.Logger().WithField("url", c.URL).Info("New client")
	client, err := agentClient.NewAgentClient(ctx, c.URL, c.dialTimout)
	if err != nil {
		c.dead = true
		return err
	}

	c.installReqFunc(client)
	c.client = client

	return nil
}

func (c *Agent) disconnect(ctx context.Context) error {
	c.Lock()
	defer c.Unlock()

	if c.client == nil {
		return nil
	}

	if err := c.client.Close(); err != nil && grpcStatus.Convert(err).Code() != codes.Canceled {
		return err
	}

	c.client = nil
	c.reqHandlers = nil

	return nil
}

type reqFunc func(context.Context, interface{}) (interface{}, error)

func (c *Agent) installReqFunc(client *agentClient.AgentClient) {
	c.reqHandlers = make(map[string]reqFunc)
	c.reqHandlers[grpcPullImageRequest] = func(ctx context.Context, req interface{}) (interface{}, error) {
		return c.client.ImageServiceClient.PullImage(ctx, req.(*grpc.PullImageRequest))
	}
}

func (c *Agent) sendReq(spanCtx context.Context, request interface{}) (interface{}, error) {
	if err := c.connect(spanCtx); err != nil {
		return nil, err
	}

	if !c.keepConn {
		defer c.disconnect(spanCtx)
	}

	msgName := proto.MessageName(request.(proto.Message))

	c.Lock()

	if c.reqHandlers == nil {
		return nil, errors.New("Client has already disconnected")
	}

	handler := c.reqHandlers[msgName]
	if msgName == "" || handler == nil {
		return nil, errors.New("Invalid request type")
	}

	c.Unlock()

	message := request.(proto.Message)
	ctx, cancel := context.WithTimeout(spanCtx, defaultRequestTimeout)
	if cancel != nil {
		defer cancel()
	}
	c.Logger().WithField("name", msgName).WithField("req", message.String()).Trace("sending request")

	return handler(ctx, request)
}

func (c *Agent) PullImage(ctx context.Context, req *image.PullImageReq) (*image.PullImageResp, error) {
	cid, err := getContainerID(req.Image)
	if err != nil {
		return nil, err
	}

	// Create dir for store unionfs image (based on sefs)
	sefsDir := filepath.Join(c.Bundle, "rootfs/images/", cid, "sefs")
	lowerDir := filepath.Join(sefsDir, "lower")
	upperDir := filepath.Join(sefsDir, "upper")
	for _, dir := range []string{lowerDir, upperDir} {
		if err := os.MkdirAll(dir, 0711); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}

	r := &grpc.PullImageRequest{
		Image:       req.Image,
		ContainerId: cid,
	}
	resp, err := c.sendReq(ctx, r)
	if err != nil {
		c.Logger().Errorf("agent enclave container pull image err. %v", err)
		return nil, err
	}
	response := resp.(*grpc.PullImageResponse)
	return &image.PullImageResp{
		ImageRef: response.ImageRef,
	}, nil
}

func createAgentContainer(ctx context.Context, s *service, r *taskAPI.CreateTaskRequest) (*runc.Container, error) {
	dir := filepath.Join(agentContainerRootDir, r.ID)
	upperDir := path.Join(dir, "upper")
	workDir := path.Join(dir, "work")
	destDir := path.Join(dir, "merged")
	for _, dir := range []string{upperDir, workDir, destDir} {
		if err := os.MkdirAll(dir, 0711); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}

	var options []string
	// Set index=off when mount overlayfs
	options = append(options, "index=off")
	options = append(options,
		fmt.Sprintf("lowerdir=%s", filepath.Join(agentContainerPath, "rootfs")),
		fmt.Sprintf("workdir=%s", workDir),
		fmt.Sprintf("upperdir=%s", upperDir),
	)
	r.Rootfs = append(r.Rootfs, &types.Mount{
		Type:    "overlay",
		Source:  "overlay",
		Options: options,
	})
	r.Bundle = destDir

	fs.CopyFile(filepath.Join(r.Bundle, "config.json"), filepath.Join(agentContainerPath, "config.json"))

	// Create Stdout and Stderr file for agent enclave container
	r.Stdout = filepath.Join(agentContainerRootDir, r.ID, r.ID+"-stdout")
	r.Stderr = filepath.Join(agentContainerRootDir, r.ID, r.ID+"-stderr")
	for _, file := range []string{r.Stdout, r.Stderr} {
		f, err := os.Create(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
	}

	agentContainer, err := runc.NewContainer(ctx, s.platform, r)
	if err != nil {
		return nil, err
	}

	return agentContainer, nil
}

// Cleanup the agent enclave container resource
func cleanupAgentContainer(ctx context.Context, id string) error {
	var cfg shim_config.Config
	if _, err := toml.DecodeFile(constants.ConfigurationPath, &cfg); err != nil {
		return err
	}
	rootdir := cfg.Containerd.AgentContainerRootDir
	path := filepath.Join(rootdir, id, "merged")

	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return err
	}
	runtime, err := runc.ReadRuntime(path)
	if err != nil {
		return err
	}
	opts, err := runc.ReadOptions(path)
	if err != nil {
		return err
	}
	root := process.RuncRoot
	if opts != nil && opts.Root != "" {
		root = opts.Root
	}

	shimLog.WithFields(logrus.Fields{
		"root":    root,
		"path":    path,
		"ns":      ns,
		"runtime": runtime,
	}).Debug("agent enclave Container Cleanup()")

	r := process.NewRunc(root, path, ns, runtime, "", false)
	if err := r.Delete(ctx, id, &runcC.DeleteOpts{
		Force: true,
	}); err != nil {
		logrus.WithError(err).Warn("failed to remove runc agent enclave container")
	}
	if err := mount.UnmountAll(filepath.Join(path, "rootfs"), 0); err != nil {
		logrus.WithError(err).Warn("failed to cleanup rootfs mount")
	}
	if err := os.RemoveAll(filepath.Join(rootdir, id)); err != nil {
		logrus.WithError(err).Warn("failed to remove agent enclave container path")
	}

	return nil
}
