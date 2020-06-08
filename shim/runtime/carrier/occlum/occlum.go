package occlum

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/runtime/v2/task"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/BurntSushi/toml"

	"github.com/alibaba/inclavare-containers/shim/runtime/config"
	shim_config "github.com/alibaba/inclavare-containers/shim/config"
	"github.com/alibaba/inclavare-containers/shim/runtime/carrier"
	"github.com/alibaba/inclavare-containers/shim/runtime/v2/rune/constants"
	carr_const "github.com/alibaba/inclavare-containers/shim/runtime/carrier/constants"
)

const (
	defaultNamespace = "default"
	//occlumEnclaveBuilderImage  = "docker.io/occlum/occlum:0.12.0-ubuntu18.04"
	buildOcclumEnclaveFileName = "build_occulum_enclave.sh"
	replaceOcclumImageScript   = "replace_occlum_image.sh"
	//containerdAddress          = "/run/containerd/containerd.sock"
	rootfsDirName  = "rootfs"
	encalveDataDir = "data"
	//sgxToolSign                = "/opt/intel/sgxsdk/bin/x64/sgx_sign"
)

var _ carrier.Carrier = &occlum{}

type occlum struct {
	context       context.Context
	bundle        string
	workDirectory string
	entryPoints   []string
	configPath    string
	spec          *specs.Spec
	shimConfig    *shim_config.Config
}

// NewOcclumCarrier returns an carrier instance of occlum.
func NewOcclumCarrier(ctx context.Context, bundle string) (carrier.Carrier, error) {
	var cfg shim_config.Config
	if _, err := toml.DecodeFile(constants.ConfigurationPath, &cfg); err != nil {
		return nil, err
	}

	setLogLevel(cfg.LogLevel)

	return &occlum{
		context:    ctx,
		bundle:     bundle,
		shimConfig: &cfg,
	}, nil
}

// Name impl Carrier.
func (c *occlum) Name() string {
	return "occlum"
}

// BuildUnsignedEnclave impl Carrier.
func (c *occlum) BuildUnsignedEnclave(req *task.CreateTaskRequest, args *carrier.BuildUnsignedEnclaveArgs) (
	unsignedEnclave string, err error) {

	// Initialize environment variables for occlum in config.json
	if err := c.initBundleConfig(); err != nil {
		return "", err
	}

	namespace, ok := namespaces.Namespace(c.context)
	logrus.Debugf("BuildUnsignedEnclave: get namespace %s, containerdAddress: %s",
		namespace, c.shimConfig.Containerd.Socket)
	if !ok {
		namespace = defaultNamespace
	}

	// Create a new client connected to the default socket path for containerd.
	client, err := containerd.New(c.shimConfig.Containerd.Socket)
	if err != nil {
		return "", fmt.Errorf("failed to create containerd client. error: %++v", err)
	}
	defer client.Close()

	logrus.Debugf("BuildUnsignedEnclave: get containerd client successfully")

	// Create a new context with "k8s.io" namespace
	ctx, cancle := context.WithTimeout(context.Background(), time.Minute*10)
	defer cancle()
	ctx = namespaces.WithNamespace(c.context, namespace)

	if err = createNamespaceIfNotExist(client, namespace); err != nil {
		return "", err
	}

	// pull the image to be used to build enclave.
	occlumEnclaveBuilderImage := c.shimConfig.EnclaveRuntime.Occlum.BuildImage
	image, err := client.Pull(ctx, occlumEnclaveBuilderImage, containerd.WithPullUnpack)
	if err != nil {
		return "", fmt.Errorf("failed to pull image %s. error: %++v", occlumEnclaveBuilderImage, err)
	}

	logrus.Debugf("BuildUnsignedEnclave: pull image %s successfully", occlumEnclaveBuilderImage)

	// Generate the containerID.
	rand.Seed(time.Now().UnixNano())
	containerId := fmt.Sprintf("occlum-enclave-builder-%s", strconv.FormatInt(rand.Int63(), 16))
	snapshotId := fmt.Sprintf("occlum-enclave-builder-snapshot-%s", strconv.FormatInt(rand.Int63(), 16))

	logrus.Debugf("BuildUnsignedEnclave: containerId: %s, snapshotId: %s", containerId, snapshotId)

	if err := os.Mkdir(filepath.Join(req.Bundle, encalveDataDir), 0755); err != nil {
		return "", err
	}

	// Create a shell script which is used to build occlum enclave.
	buildEnclaveScript := filepath.Join(req.Bundle, encalveDataDir, buildOcclumEnclaveFileName)
	if err := ioutil.WriteFile(buildEnclaveScript, []byte(fmt.Sprintf(carr_const.BuildOcclumEnclaveScript,
		c.workDirectory, c.entryPoints[0], c.configPath)), os.ModePerm); err != nil {
		return "", err
	}

	replaceImagesScript := filepath.Join(req.Bundle, encalveDataDir, replaceOcclumImageScript)
	if err := ioutil.WriteFile(replaceImagesScript, []byte(carr_const.ReplaceOcclumImageScript), os.ModePerm); err != nil {
		return "", err
	}

	// Create rootfs mount points.
	mounts := make([]specs.Mount, 0)
	rootfsMount := specs.Mount{
		Destination: filepath.Join("/", rootfsDirName),
		Type:        "bind",
		Source:      filepath.Join(req.Bundle, rootfsDirName),
		Options:     []string{"rbind", "rw"},
	}
	dataMount := specs.Mount{
		Destination: filepath.Join("/", encalveDataDir),
		Type:        "bind",
		Source:      filepath.Join(req.Bundle, encalveDataDir),
		Options:     []string{"rbind", "rw"},
	}

	logrus.Debugf("BuildUnsignedEnclave: rootfsMount source: %s, destination: %s",
		rootfsMount.Source, rootfsMount.Destination)

	mounts = append(mounts, rootfsMount, dataMount)
	// create a container
	container, err := client.NewContainer(
		ctx,
		containerId,
		containerd.WithImage(image),
		containerd.WithNewSnapshot(snapshotId, image),
		containerd.WithNewSpec(oci.WithImageConfig(image),
			oci.WithProcessArgs("/bin/bash", filepath.Join("/", encalveDataDir, buildOcclumEnclaveFileName)),
			//FIXME debug
			//oci.WithProcessArgs("sleep", "infinity"),
			oci.WithPrivileged,
			oci.WithMounts(mounts),
		),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create container by image %s. error: %++v",
			occlumEnclaveBuilderImage, err)
	}
	defer container.Delete(ctx, containerd.WithSnapshotCleanup)

	// Create a task from the container.
	task, err := container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
	if err != nil {
		return "", err
	}
	defer task.Delete(ctx)
	logrus.Debugf("BuildUnsignedEnclave: create task successfully")

	// Wait before calling start
	exitStatusC, err := task.Wait(ctx)
	if err != nil {
		return "", err
	}

	// Call start() on the task to execute the building scripts.
	if err := task.Start(ctx); err != nil {
		return "", err
	}

	// Wait for the process to fully exit and print out the exit status
	status := <-exitStatusC
	code, _, err := status.Result()
	if err != nil {
		return "", fmt.Errorf("container exited abnormaly with exit code %d. error: %++v", code, err)
	} else if code != 0 {
		return "", fmt.Errorf("container exited abnormaly with exit code %d", code)
	}

	enclavePath := filepath.Join(req.Bundle, rootfsDirName, c.workDirectory, ".occlum/build/lib/libocclum-libos.so")

	logrus.Debugf("BuildUnsignedEnclave: exit code: %d. enclavePath: %s", code, enclavePath)

	return enclavePath, nil
}

// GenerateSigningMaterial impl Carrier.
func (c *occlum) GenerateSigningMaterial(req *task.CreateTaskRequest, args *carrier.CommonArgs) (
	signingMaterial string, err error) {

	signingMaterial = filepath.Join(req.Bundle, encalveDataDir, "enclave_sig.dat")
	args.Config = filepath.Join(req.Bundle, encalveDataDir, "Enclave.xml")
	sgxToolSign := c.shimConfig.SgxToolSign

	logrus.Debugf("GenerateSigningMaterial cmmmand: %s gendata -enclave %s -config %s -out %s",
		sgxToolSign, args.Enclave, args.Config, signingMaterial)

	gendataArgs := []string{
		"gendata",
		"-enclave",
		args.Enclave,
		"-config",
		args.Config,
		"-out", signingMaterial,
	}
	cmd := exec.Command(sgxToolSign, gendataArgs...)
	if result, err := cmd.Output(); err != nil {
		return "", fmt.Errorf("GenerateSigningMaterial: sgx_sign gendata failed. error: %v %s", err, string(result))
	}

	return signingMaterial, nil
}

// CascadeEnclaveSignature impl Carrier.
func (c *occlum) CascadeEnclaveSignature(req *task.CreateTaskRequest, args *carrier.CascadeEnclaveSignatureArgs) (
	signedEnclave string, err error) {

	signedEnclave = filepath.Join(
		req.Bundle,
		rootfsDirName,
		c.workDirectory,
		".occlum/build/lib/libocclum-libos.signed.so")
	sgxToolSign := c.shimConfig.SgxToolSign

	logrus.Debugf("CascadeEnclaveSignature cmmmand: %s catsig -enclave %s -config %s -out %s -key %s -sig %s -unsigned %s",
		sgxToolSign, args.Enclave, args.Config, signedEnclave, args.Key, args.Signature, args.SigningMaterial)

	catsigArgs := []string{
		"catsig",
		"-enclave",
		args.Enclave,
		"-config",
		args.Config,
		"-out",
		signedEnclave,
		"-key",
		args.Key,
		"-sig",
		args.Signature,
		"-unsigned",
		args.SigningMaterial,
	}
	cmd := exec.Command(sgxToolSign, catsigArgs...)
	if result, err := cmd.Output(); err != nil {
		return "", fmt.Errorf("CascadeEnclaveSignature: sgx_sign catsig failed. error: %v %s", err, string(result))
	}
	return signedEnclave, nil
}

// Cleanup impl Carrier.
func (c *occlum) Cleanup() error {
	//TODO
	return nil
}

func (c *occlum) initBundleConfig() error {
	configPath := filepath.Join(c.bundle, "config.json")
	spec, err := config.LoadSpec(configPath)
	if err != nil {
		return err
	}
	c.workDirectory = spec.Process.Cwd
	c.entryPoints = spec.Process.Args
	enclaveRuntimePath := fmt.Sprintf("%s/liberpal-occlum.so", c.workDirectory)
	envs := map[string]string{
		carr_const.EnclaveRuntimePathKeyName: enclaveRuntimePath,
		carr_const.EnclaveTypeKeyName:        string(carr_const.IntelSGX),
		carr_const.EnclaveRuntimeArgsKeyName: carr_const.DefaultEnclaveRuntimeArgs,
	}

	if occlumConfigPath, ok := config.GetEnv(spec, carr_const.OcclumConfigPathKeyName); ok {
		c.configPath = occlumConfigPath
	}

	c.spec = spec

	if err := config.UpdateEnvs(spec, envs, false); err != nil {
		return err
	}

	return config.SaveSpec(configPath, spec)
}

func createNamespaceIfNotExist(client *containerd.Client, namespace string) error {
	svc := client.NamespaceService()

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*60)
	defer cancel()
	nses, err := svc.List(ctx)
	if err != nil {
		return err
	}
	for _, ns := range nses {
		if ns == namespace {
			return nil
		}
	}

	return svc.Create(ctx, namespace, nil)
}

// generateID generates a random unique id.
func generateID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func setLogLevel(level string) {
	switch level {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "warn":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}
}
