package occlum

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/runtime/v2/task"
	epm_api "github.com/inclavare-containers/epm/pkg/epm-api/v1alpha1"
	"github.com/inclavare-containers/epm/pkg/epm/bundle-cache-pool/occlum/types"
	shim_config "github.com/inclavare-containers/shim/config"
	"github.com/inclavare-containers/shim/runtime/carrier"
	carr_const "github.com/inclavare-containers/shim/runtime/carrier/constants"
	"github.com/inclavare-containers/shim/runtime/carrier/sign"
	"github.com/inclavare-containers/shim/runtime/config"
	"github.com/inclavare-containers/shim/runtime/utils"
	"github.com/inclavare-containers/shim/runtime/v2/rune/constants"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const (
	replaceOcclumImageScript = "replace_occlum_image.sh"
	carrierScriptFileName    = "carrier.sh"
	rootfsDirName            = "rootfs"
	dataDirName              = "data"
	occlumConfigFileName     = "Occlum.json"
)

var _ carrier.Carrier = &occlum{}

type occlum struct {
	context           context.Context
	bundle            string
	workDirectory     string
	entryPoints       []string
	configPath        string
	spec              *specs.Spec
	shimConfig        *shim_config.Config
	bundleCacheConfig *bundleCacheConfig
}

// NewOcclumCarrier returns an carrier instance of occlum.
func NewOcclumCarrier(ctx context.Context, bundle string) (carrier.Carrier, error) {
	var cfg shim_config.Config
	var conn *grpc.ClientConn
	var err error
	if _, err := toml.DecodeFile(constants.ConfigurationPath, &cfg); err != nil {
		return nil, err
	}
	setLogLevel(cfg.LogLevel)
	if cfg.Epm.Socket == "" {
		logrus.Warnf("epm socket file is not exist")
	} else {
		// Set up a connection to the server.
		address := fmt.Sprintf("unix://%s", cfg.Epm.Socket)
		conn, err = grpc.Dial(address, grpc.WithInsecure())
		if err != nil {
			log.Fatalf("did not connect address %s: %v", address, err)
		}
	}
	return &occlum{
		context:    ctx,
		bundle:     bundle,
		shimConfig: &cfg,
		bundleCacheConfig: &bundleCacheConfig{
			epmConnection: conn,
			cacheIDMap:    make(map[types.BundleCachePoolType]string),
		},
	}, nil
}

// Name impl Carrier.
func (o *occlum) Name() string {
	return "occlum"
}

// BuildUnsignedEnclave impl Carrier.
func (o *occlum) BuildUnsignedEnclave(req *task.CreateTaskRequest, args *carrier.BuildUnsignedEnclaveArgs) (
	unsignedEnclave string, err error) {
	timeStart := time.Now()
	ts := timeStart
	defer logrus.Debugf("BuildUnsignedEnclave: total time cost: %d", (time.Now().Sub(ts))/time.Second)
	// Initialize environment variables for occlum in config.json
	if err := o.initBundleConfig(); err != nil {
		return "", err
	}

	// Copy the script files that are used to build enclave.so by occlum into rootfs
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

	occlumConfigPath := filepath.Join(dataDir, occlumConfigFileName)
	if err := o.saveOcclumConfig(occlumConfigPath); err != nil {
		return "", err
	}
	// Load bundle cache0 to occlum instance directory
	timeStart = time.Now()
	var inputs0 bundleCache0Inputs
	var inputs1 bundleCache1Inputs
	digest, ok := config.GetEnv(o.spec, constants.EnvKeyImageDigest)
	if !ok {
		logrus.Warningf("BuildUnsignedEnclave: environment variable %s is not exist.", constants.EnvKeyImageDigest)
	}
	inputs0 = bundleCache0Inputs{
		imageDigest: digest,
	}
	inputs1 = bundleCache1Inputs{
		bundleCache0Inputs: inputs0,
		occlumConfigPath:   occlumConfigPath,
		occlumLibOSPath:    o.shimConfig.EnclaveRuntime.Occlum.EnclaveLibOSPath,
	}
	o.bundleCacheConfig.inputsCache.inputs0 = inputs0
	o.bundleCacheConfig.inputsCache.inputs1 = inputs1
	cacheType := types.BundleCache0PoolType
	occlumInstanceDir := filepath.Join(rootfsDir, o.workDirectory)
	enclavePath := filepath.Join(occlumInstanceDir, "./build/lib/libocclum-libos.so")
	cache0ID, err := o.loadBundleCache(cacheType, &inputs0, occlumInstanceDir)
	if err != nil {
		logrus.Warningf("BuildUnsignedEnclave: load bundle cache %s failed. err: %++v", cacheType, err)
		if e, err := o.do_buildUnsignedEnclave(dataDir, rootfsDir, occlumConfigPath); err != nil {
			return e, err
		}
	} else {
		o.bundleCacheConfig.cacheLevel = types.BundleCache0PoolType
		o.bundleCacheConfig.cacheIDMap[types.BundleCache0PoolType] = cache0ID
		logrus.Debugf("BuildUnsignedEnclave: load bundle cache %s time cost: %d", cacheType, (time.Now().Sub(timeStart))/time.Second)

		// Load bundle cache1 to occlum instance directory
		timeStart = time.Now()
		cacheType = types.BundleCache1PoolType
		if cache1ID, err := o.loadBundleCache(cacheType, &inputs1, occlumInstanceDir); err != nil {
			logrus.Warningf("BuildUnsignedEnclave: load bundle cache %s failed. err: %++v", cacheType, err)
			if e, err := o.do_buildUnsignedEnclaveWithBundleCache0(dataDir, rootfsDir, occlumConfigPath); err != nil {
				return e, err
			}
		} else {
			o.bundleCacheConfig.cacheLevel = cacheType
			o.bundleCacheConfig.cacheIDMap[types.BundleCache1PoolType] = cache1ID
			logrus.Debugf("BuildUnsignedEnclave: load bundle cache %s time cost: %d", cacheType, (time.Now().Sub(timeStart))/time.Second)
		}
	}

	if o.bundleCacheConfig.cacheLevel == "" {
		// Save bundle cache0
		if cache, err := o.saveBundleCache(types.BundleCache0PoolType, &inputs0, nil, occlumInstanceDir); err != nil {
			logrus.Warningf("BuildUnsignedEnclave: save bundle cache %s failed. error: %++v", types.BundleCache0PoolType, err)
		} else if cache != nil {
			cache0ID = cache.ID
			o.bundleCacheConfig.cacheIDMap[types.BundleCache0PoolType] = cache0ID
		}
	}
	if o.bundleCacheConfig.cacheLevel == "" || o.bundleCacheConfig.cacheLevel == types.BundleCache0PoolType {
		// Save bundle cache1
		logrus.Debugf("BuildUnsignedEnclave: inputs1: %++v", inputs1)
		if cache, err := o.saveBundleCache(types.BundleCache1PoolType, &inputs1, &epm_api.Cache{
			Type: string(types.BundleCache0PoolType),
			ID:   cache0ID},
			occlumInstanceDir); err != nil {
			logrus.Warningf("BuildUnsignedEnclave: save bundle cache %s failed. error: %++v", types.BundleCache1PoolType, err)
		} else if cache != nil {
			o.bundleCacheConfig.cacheIDMap[types.BundleCache1PoolType] = cache.ID
		}
	}

	return enclavePath, nil
}

func (o *occlum) do_buildUnsignedEnclave(dataDir, rootfsDir, occlumConfigPath string) (
	unsignedEnclave string, err error) {
	timeStart := time.Now()
	cmdArgs := []string{
		filepath.Join(dataDir, carrierScriptFileName),
		"--action", "buildUnsignedEnclave",
		"--work_dir", o.workDirectory,
		"--rootfs", rootfsDir,
		"--occlum_config_path", occlumConfigPath,
	}
	logrus.Debugf("BuildUnsignedEnclave: command: %v", cmdArgs)
	if _, err := utils.ExecCommand("/bin/bash", cmdArgs...); err != nil {
		logrus.Errorf("BuildUnsignedEnclave: execute command failed. error: %++v", err)
		return "", err
	}
	logrus.Debugf("BuildUnsignedEnclave: init and build enclave time cost: %d", (time.Now().Sub(timeStart))/time.Second)
	return
}

func (o *occlum) do_buildUnsignedEnclaveWithBundleCache0(dataDir, rootfsDir, occlumConfigPath string) (
	unsignedEnclave string, err error) {
	timeStart := time.Now()
	cmdArgs := []string{
		filepath.Join(dataDir, carrierScriptFileName),
		"--action", "buildUnsignedEnclaveWithBundleCache0",
		"--work_dir", o.workDirectory,
		"--rootfs", rootfsDir,
		"--occlum_config_path", occlumConfigPath,
	}
	logrus.Debugf("BuildUnsignedEnclave: command: %v", cmdArgs)
	if _, err := utils.ExecCommand("/bin/bash", cmdArgs...); err != nil {
		logrus.Errorf("BuildUnsignedEnclave: execute command failed. error: %++v", err)
		return "", err
	}
	logrus.Debugf("BuildUnsignedEnclave: build enclave with bundle cache0 time cost: %d", (time.Now().Sub(timeStart))/time.Second)
	return
}

// GenerateSigningMaterial impl Carrier.
func (o *occlum) GenerateSigningMaterial(req *task.CreateTaskRequest, args *carrier.CommonArgs) (
	signingMaterial string, err error) {
	timeStart := time.Now()
	rootfsDir := filepath.Join(req.Bundle, rootfsDirName)
	dataDir := filepath.Join(req.Bundle, dataDirName)
	signingMaterial = filepath.Join(rootfsDir, o.workDirectory, "enclave_sig.dat")
	args.Config = filepath.Join(rootfsDir, o.workDirectory, "build/Enclave.xml")
	cmdArgs := []string{
		filepath.Join(dataDir, carrierScriptFileName),
		"--action", "generateSigningMaterial",
		"--enclave_config_path", args.Config,
		"--unsigned_enclave_path", args.Enclave,
		"--unsigned_material_path", signingMaterial,
	}
	logrus.Debugf("GenerateSigningMaterial: sgx_sign gendata command: %v", cmdArgs)
	if _, err := utils.ExecCommand("/bin/bash", cmdArgs...); err != nil {
		logrus.Errorf("GenerateSigningMaterial: sgx_sign gendata failed. error: %++v", err)
		return "", err
	}
	logrus.Debugf("GenerateSigningMaterial: sgx_sign gendata successfully")
	defer logrus.Debugf("GenerateSigningMaterial: total time cost: %d", (time.Now().Sub(timeStart))/time.Second)
	return signingMaterial, nil
}

// SignMaterial impl Carrier.
func (o *occlum) SignMaterial(req *task.CreateTaskRequest, signingMaterial, serverAddress string) (publicKey, signature string, err error) {
	if serverAddress == "" {
		return sign.MockSign(signingMaterial)
	}
	publicKeyFile, err := sign.GetPublicKey(serverAddress)
	if err != nil {
		return "", "", err
	}
	defer os.Remove(publicKeyFile)
	inputs2 := bundleCache2Inputs{
		publicKeyFilePath:  publicKeyFile,
		bundleCache1Inputs: o.bundleCacheConfig.inputsCache.inputs1,
	}
	o.bundleCacheConfig.inputsCache.inputs2 = inputs2
	rootfsDir := filepath.Join(req.Bundle, rootfsDirName)
	occlumInstanceDir := filepath.Join(rootfsDir, o.workDirectory)
	cacheType := types.BundleCache2PoolType
	if cache2ID, err := o.loadBundleCache(cacheType, &inputs2, occlumInstanceDir); err != nil {
		logrus.Warningf("SignMaterial: load bundle cache %s failed. err: %++v", cacheType, err)
		return sign.RemoteSign(signingMaterial, serverAddress)
	} else {
		o.bundleCacheConfig.cacheLevel = cacheType
		o.bundleCacheConfig.cacheIDMap[cacheType] = cache2ID
	}
	return "", "", nil
}

// CascadeEnclaveSignature impl Carrier.
func (o *occlum) CascadeEnclaveSignature(req *task.CreateTaskRequest, args *carrier.CascadeEnclaveSignatureArgs) (
	signedEnclave string, err error) {
	timeStart := time.Now()
	rootfsDir := filepath.Join(req.Bundle, rootfsDirName)
	dataDir := filepath.Join(req.Bundle, dataDirName)
	occlumInstanceDir := filepath.Join(rootfsDir, o.workDirectory)
	signedEnclave = filepath.Join(rootfsDir, o.workDirectory, "./build/lib/libocclum-libos.signed.so")
	cacheType := types.BundleCache2PoolType
	if o.bundleCacheConfig.cacheLevel == cacheType {
		return "", nil
	}
	cmdArgs := []string{
		filepath.Join(dataDir, carrierScriptFileName),
		"--action", "cascadeEnclaveSignature",
		"--enclave_config_path", args.Config,
		"--unsigned_enclave_path", args.Enclave,
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
	cache1Id := o.bundleCacheConfig.cacheIDMap[types.BundleCache1PoolType]
	inputs2 := &bundleCache2Inputs{
		publicKeyFilePath:  args.Key,
		bundleCache1Inputs: o.bundleCacheConfig.inputsCache.inputs1,
	}
	// Save bundle cache2
	if _, err := o.saveBundleCache(cacheType, inputs2, &epm_api.Cache{
		ID:   cache1Id,
		Type: string(types.BundleCache1PoolType),
	}, occlumInstanceDir); err != nil {
		logrus.Warningf("CascadeEnclaveSignature: save bundle cache %s failed. error: %++v", cacheType, err)
	}
	logrus.Debugf("CascadeEnclaveSignature: total time cost: %d", (time.Now().Sub(timeStart))/time.Second)
	return signedEnclave, nil
}

// Cleanup impl Carrier.
func (o *occlum) Cleanup(err error) error {
	timeStart := time.Now()
	if o.bundleCacheConfig.epmConnection != nil {
		if err != nil {
			cacheId := o.bundleCacheConfig.cacheIDMap[types.BundleCache0PoolType]
			if cacheId != "" {
				if err := o.deleteBundleCache(types.BundleCache0PoolType, cacheId); err != nil {
					logrus.Errorf("Cleanup: %v", err)
				}
			}
		}
		o.bundleCacheConfig.epmConnection.Close()
	}
	logrus.Debugf("Cleanup: total time cost: %d", (time.Now().Sub(timeStart))/time.Second)
	return nil
}

func (o *occlum) initBundleConfig() error {
	configPath := filepath.Join(o.bundle, "config.json")
	spec, err := config.LoadSpec(configPath)
	if err != nil {
		return err
	}
	o.workDirectory = spec.Process.Cwd
	o.entryPoints = spec.Process.Args
	enclaveRuntimePath := o.shimConfig.EnclaveRuntime.Occlum.EnclaveRuntimePath
	if enclaveRuntimePath == "" {
		enclaveRuntimePath = fmt.Sprintf("%s/liberpal-occlum.so", o.workDirectory)
	}
	envs := map[string]string{
		carr_const.EnclaveRuntimePathKeyName: enclaveRuntimePath,
		carr_const.EnclaveTypeKeyName:        string(carr_const.IntelSGX),
		carr_const.EnclaveRuntimeArgsKeyName: carr_const.DefaultEnclaveRuntimeArgs,
	}
	o.spec = spec
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
