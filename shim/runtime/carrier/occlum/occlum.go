package occlum

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	shim_config "github.com/alibaba/inclavare-containers/shim/config"
	"github.com/alibaba/inclavare-containers/shim/runtime/carrier"
	carr_const "github.com/alibaba/inclavare-containers/shim/runtime/carrier/constants"
	"github.com/alibaba/inclavare-containers/shim/runtime/config"
	"github.com/alibaba/inclavare-containers/shim/runtime/utils"
	"github.com/alibaba/inclavare-containers/shim/runtime/v2/rune/constants"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/containerd/runtime/v2/task"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

const (
	replaceOcclumImageScript = "replace_occlum_image.sh"
	carrierScriptFileName    = "carrier.sh"
	rootfsDirName            = "rootfs"
	dataDirName              = "data"
)

var _ carrier.Carrier = &occlum{}

type occlumBuildTask struct {
	client    *containerd.Client
	container *containerd.Container
	task      *containerd.Task
}

type occlum struct {
	context       context.Context
	bundle        string
	workDirectory string
	entryPoints   []string
	configPath    string
	task          *occlumBuildTask
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
		task:       &occlumBuildTask{},
	}, nil
}

// Name impl Carrier.
func (c *occlum) Name() string {
	return "occlum"
}

// BuildUnsignedEnclave impl Carrier.
func (c *occlum) BuildUnsignedEnclave(req *task.CreateTaskRequest, args *carrier.BuildUnsignedEnclaveArgs) (
	unsignedEnclave string, err error) {
	timeStart := time.Now()
	ts := timeStart
	// Initialize environment variables for occlum in config.json
	if err := c.initBundleConfig(); err != nil {
		return "", err
	}

	// Copy the script files that are used to build encalve.so by occlum into rootfs
	rootfsDir := filepath.Join(req.Bundle, rootfsDirName)
	dataDir := filepath.Join(req.Bundle, dataDirName)
	os.MkdirAll(dataDir, 0755)

	replaceImagesScript := filepath.Join(dataDir, replaceOcclumImageScript)
	if err := ioutil.WriteFile(replaceImagesScript, []byte(carr_const.ReplaceOcclumImageScript), os.ModePerm); err != nil {
		return "", err
	}

	carrierScript := filepath.Join(dataDir, carrierScriptFileName)
	if err := ioutil.WriteFile(carrierScript, []byte(carr_const.CarrierScript), os.ModePerm); err != nil {
		return "", err
	}

	// Execute the carrier script to generate the unsigned enclave.so in rootfs
	cmdArgs := []string{
		filepath.Join(dataDir, carrierScriptFileName),
		"--action", "buildUnsignedEnclave",
		"--entry_point", c.entryPoints[0],
		"--work_dir", c.workDirectory,
		"--rootfs", rootfsDir,
	}
	var occlumConfigPath string
	if c.configPath != "" {
		occlumConfigPath = filepath.Join(rootfsDir, c.configPath)
	} else {
		c.configPath = "Occlum.json"
		occlumConfigPath = filepath.Join(dataDir, c.configPath)
		if err := c.saveOcclumConfig(occlumConfigPath); err != nil {
			return "", err
		}
	}
	cmdArgs = append(cmdArgs, "--occlum_config_path", occlumConfigPath)
	logrus.Debugf("BuildUnsignedEnclave: command: %v", cmdArgs)
	timeStart = time.Now()
	if _, err := utils.ExecCommand("/bin/bash", cmdArgs...); err != nil {
		logrus.Errorf("BuildUnsignedEnclave: execute command failed. error: %++v", err)
		return "", err
	}
	logrus.Debugf("BuildUnsignedEnclave: init and build enclave time cost: %d", (time.Now().Sub(timeStart))/time.Second)
	enclavePath := filepath.Join(rootfsDir, c.workDirectory, "./build/lib/libocclum-libos.so")
	logrus.Debugf("BuildUnsignedEnclave: total time cost: %d", (time.Now().Sub(ts))/time.Second)
	return enclavePath, nil
}

// GenerateSigningMaterial impl Carrier.
func (c *occlum) GenerateSigningMaterial(req *task.CreateTaskRequest, args *carrier.CommonArgs) (
	signingMaterial string, err error) {
	timeStart := time.Now()
	rootfsDir := filepath.Join(req.Bundle, rootfsDirName)
	dataDir := filepath.Join(req.Bundle, dataDirName)
	signingMaterial = filepath.Join(rootfsDir, c.workDirectory, "enclave_sig.dat")
	args.Config = filepath.Join(rootfsDir, c.workDirectory, "Enclave.xml")
	cmdArgs := []string{
		filepath.Join(dataDir, carrierScriptFileName),
		"--action", "generateSigningMaterial",
		"--enclave_config_path", args.Config,
		"--unsigned_encalve_path", args.Enclave,
		"--unsigned_material_path", signingMaterial,
	}
	logrus.Debugf("GenerateSigningMaterial: sgx_sign gendata command: %v", cmdArgs)
	if _, err := utils.ExecCommand("/bin/bash", cmdArgs...); err != nil {
		logrus.Errorf("GenerateSigningMaterial: sgx_sign gendata failed. error: %++v", err)
		return "", err
	}
	logrus.Debugf("GenerateSigningMaterial: sgx_sign gendata successfully")
	logrus.Debugf("GenerateSigningMaterial: total time cost: %d", (time.Now().Sub(timeStart))/time.Second)
	return signingMaterial, nil
}

// CascadeEnclaveSignature impl Carrier.
func (c *occlum) CascadeEnclaveSignature(req *task.CreateTaskRequest, args *carrier.CascadeEnclaveSignatureArgs) (
	signedEnclave string, err error) {
	timeStart := time.Now()
	rootfsDir := filepath.Join(req.Bundle, rootfsDirName)
	dataDir := filepath.Join(req.Bundle, dataDirName)
	signedEnclave = filepath.Join(rootfsDir, c.workDirectory, "./build/lib/libocclum-libos.signed.so")
	cmdArgs := []string{
		filepath.Join(dataDir, carrierScriptFileName),
		"--action", "cascadeEnclaveSignature",
		"--enclave_config_path", args.Config,
		"--unsigned_encalve_path", args.Enclave,
		"--unsigned_material_path", args.SigningMaterial,
		"--signed_enclave_path", signedEnclave,
		"--public_key_path", args.Key,
		"--signature_path", args.Signature,
	}
	logrus.Debugf("CascadeEnclaveSignature: sgx_sign catsig command: %v", cmdArgs)
	if _, err := utils.ExecCommand("/bin/bash", cmdArgs...); err != nil {
		logrus.Errorf("CascadeEnclaveSignature: sgx_sign catsig failed. error: %++v", err)
		return "", err
	}
	logrus.Debugf("CascadeEnclaveSignature: sgx_sign catsig successfully")
	logrus.Debugf("CascadeEnclaveSignature: total time cost: %d", (time.Now().Sub(timeStart))/time.Second)
	return signedEnclave, nil
}

// Cleanup impl Carrier.
func (c *occlum) Cleanup() error {
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
	enclaveRuntimePath := c.shimConfig.EnclaveRuntime.Occlum.EnclaveRuntimePath
	if enclaveRuntimePath == "" {
		enclaveRuntimePath = fmt.Sprintf("%s/liberpal-occlum.so", c.workDirectory)
	}
	envs := map[string]string{
		carr_const.EnclaveRuntimePathKeyName: enclaveRuntimePath,
		carr_const.EnclaveTypeKeyName:        string(carr_const.IntelSGX),
		carr_const.EnclaveRuntimeArgsKeyName: carr_const.DefaultEnclaveRuntimeArgs,
	}
	c.spec = spec
	if err := config.UpdateEnvs(spec, envs, false); err != nil {
		return err
	}
	return config.SaveSpec(configPath, spec)
}

func (o *occlum) saveOcclumConfig(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	cfg := GetDefaultOcclumConfig()
	cfg.ApplyEnvs(o.spec.Process.Env)
	cfg.ApplyEntrypoints([]string{o.entryPoints[0]})
	bytes, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, bytes, 0644)
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

func (c *occlum) execTask(args ...string) error {
	container := *c.task.container
	t := *c.task.task
	if container == nil || t == nil {
		return fmt.Errorf("task is not exist")
	}
	spec, err := container.Spec(c.context)
	if err != nil {
		logrus.Errorf("execTask: get container spec failed. error: %++v", err)
		return err
	}
	pspec := spec.Process
	pspec.Terminal = false
	pspec.Args = args

	cioOpts := []cio.Opt{cio.WithStdio, cio.WithFIFODir("/run/containerd/fifo")}
	ioCreator := cio.NewCreator(cioOpts...)
	process, err := t.Exec(c.context, utils.GenerateID(), pspec, ioCreator)
	if err != nil {
		logrus.Errorf("execTask: exec process in task failed. error: %++v", err)
		return err
	}
	defer process.Delete(c.context)
	statusC, err := process.Wait(c.context)
	if err != nil {
		return err
	}
	sigc := commands.ForwardAllSignals(c.context, process)
	defer commands.StopCatch(sigc)

	if err := process.Start(c.context); err != nil {
		logrus.Errorf("execTask: start process failed. error: %++v", err)
		return err
	}
	status := <-statusC
	code, _, err := status.Result()
	if err != nil {
		logrus.Errorf("execTask: exec process failed. error: %++v", err)
		return err
	}
	if code != 0 {
		return fmt.Errorf("process exit abnormaly. exitCode: %d, error: %++v", code, status.Error())
	}
	logrus.Debugf("execTask: exec successfully.")
	return nil
}
