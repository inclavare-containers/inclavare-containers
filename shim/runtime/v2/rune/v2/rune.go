package v2

import (
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/pkg/process"
	taskAPI "github.com/containerd/containerd/runtime/v2/task"
	shim_config "github.com/inclavare-containers/shim/config"
	"github.com/inclavare-containers/shim/runtime/carrier"
	emptycarrier "github.com/inclavare-containers/shim/runtime/carrier/empty"
	"github.com/inclavare-containers/shim/runtime/carrier/graphene"
	"github.com/inclavare-containers/shim/runtime/carrier/occlum"
	"github.com/inclavare-containers/shim/runtime/config"
	"github.com/inclavare-containers/shim/runtime/v2/rune"
	"github.com/inclavare-containers/shim/runtime/v2/rune/constants"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// runE main flow.
func (s *service) carrierMain(req *taskAPI.CreateTaskRequest) (carrier.Carrier, error) {
	timeStart := time.Now()
	var err error
	var carr carrier.Carrier

	found, carrierKind, err := getCarrierKind(req.Bundle)
	if err != nil {
		return carr, err
	}

	if !found {
		emptycarr, _ := emptycarrier.NewEmptyCarrier()
		return emptycarr, nil
	}

	switch carrierKind {
	case rune.Occlum:
		if carr, err = occlum.NewOcclumCarrier(s.context, req.Bundle); err != nil {
			return nil, err
		}
		// mount rootfs
		timeStart = time.Now()
		err = mountRootfs(req)
		logrus.Debugf("carrierMain: mount rootfs time cost: %d", (time.Now().Sub(timeStart))/time.Second)
		defer unmountRootfs(req)
		if err != nil {
			return carr, err
		}

	case rune.Graphene:
		carr, err = graphene.NewGrapheneCarrier()
	case rune.Empty:
		carr, err = emptycarrier.NewEmptyCarrier()
	default:
		return carr, rune.ErrorUnknownCarrier
	}
	if err != nil {
		return carr, err
	}

	var cfg shim_config.Config
	if _, err := toml.DecodeFile(constants.ConfigurationPath, &cfg); err != nil {
		return nil, err
	}
	if cfg.EnclaveRuntime.SignatureMethod == constants.SignatureMethodClient {
		return carr, nil
	}
	unsignedEnclave, err := carr.BuildUnsignedEnclave(req, &carrier.BuildUnsignedEnclaveArgs{
		Bundle: req.Bundle,
	})
	if err != nil {
		return carr, err
	}
	commonArgs := carrier.CommonArgs{
		Enclave: unsignedEnclave,
	}
	signingMaterial, err := carr.GenerateSigningMaterial(req, &commonArgs)
	if err != nil {
		return carr, err
	}
	var signature string
	var publicKey string
	timeStart = time.Now()
	publicKey, signature, err = carr.SignMaterial(req, signingMaterial, cfg.Signature.ServerAddress)
	if err != nil {
		logrus.Errorf("carrierMain: sign enclave failed. %++v", err)
		return carr, err
	}
	logrus.Debugf("carrierMain: sign enclave time cost: %d", (time.Now().Sub(timeStart))/time.Second)
	commonArgs.Key = publicKey
	defer os.RemoveAll(filepath.Dir(publicKey))
	signedEnclave, err := carr.CascadeEnclaveSignature(req, &carrier.CascadeEnclaveSignatureArgs{
		CommonArgs:      commonArgs,
		SigningMaterial: signingMaterial,
		Signature:       signature,
	})
	if err != nil {
		return carr, err
	}
	logrus.Debugf("carrierMain: finished carrier: %v, signedEnclave: %s", carr, signedEnclave)
	return carr, nil
}

func getCarrierKind(bundlePath string) (found bool, value rune.CarrierKind, err error) {
	configPath := path.Join(bundlePath, "config.json")
	var spec *specs.Spec
	spec, err = config.LoadSpec(configPath)
	if err != nil {
		return
	}
	v, ok := config.GetEnv(spec, constants.EnvKeyRuneCarrier)
	if !ok {
		return true, rune.Empty, nil
	}
	value = rune.CarrierKind(v)
	if value == rune.Occlum || value == rune.Graphene || value == rune.Empty {
		found = true
		return
	}
	err = errors.Wrapf(rune.ErrorUnknownCarrier, "unexpected carrier kind: %v", value)
	return
}

func mountRootfs(req *taskAPI.CreateTaskRequest) error {
	var mounts []process.Mount
	for _, m := range req.Rootfs {
		mounts = append(mounts, process.Mount{
			Type:    m.Type,
			Source:  m.Source,
			Target:  m.Target,
			Options: m.Options,
		})
	}
	rootfs := ""
	if len(mounts) > 0 {
		rootfs = filepath.Join(req.Bundle, "rootfs")
		if err := os.Mkdir(rootfs, 0711); err != nil && !os.IsExist(err) {
			return err
		}
	}
	for _, rm := range mounts {
		m := &mount.Mount{
			Type:    rm.Type,
			Source:  rm.Source,
			Options: rm.Options,
		}
		if err := m.Mount(rootfs); err != nil {
			return errors.Wrapf(err, "failed to mount rootfs component %v", m)
		}
		logrus.Infof("mount success. src: %s, dst: %s, type: %s, options: %s", m.Source, rootfs, m.Type, m.Options)
	}
	return nil
}

func mountOCIOnRootfs(bundle string) error {
	configPath := filepath.Join(bundle, "config.json")
	spec, err := config.LoadSpec(configPath)
	if err != nil {
		return err
	}
	mounts := spec.Mounts
	for _, rm := range mounts {
		m := &mount.Mount{
			Type:    rm.Type,
			Source:  rm.Source,
			Options: rm.Options,
		}
		target := filepath.Clean(filepath.Join(bundle, "rootfs", rm.Destination))
		if err := m.Mount(target); err != nil {
			return errors.Wrapf(err, "failed to mount rootfs component %v, err: %++v", m, err)
		}
		logrus.Infof("mount success. src: %s, dst: %s, type: %s, options: %s", m.Source, target, m.Type, m.Options)
	}
	return nil
}

func unmountOCIOnRootfs(bundle string) error {
	configPath := filepath.Join(bundle, "config.json")
	spec, err := config.LoadSpec(configPath)
	if err != nil {
		return err
	}
	mounts := spec.Mounts
	for _, rm := range mounts {
		target := filepath.Clean(filepath.Join(bundle, "rootfs", rm.Destination))
		if err := mount.UnmountAll(target, 0); err != nil {
			logrus.WithError(err).Warnf("failed to cleanup mount point %s", target)
		}

	}
	return nil
}

func unmountRootfs(req *taskAPI.CreateTaskRequest) error {
	timeStart := time.Now()
	rootfs := ""
	if len(req.Rootfs) > 0 {
		rootfs = filepath.Join(req.Bundle, "rootfs")
		if err := os.Mkdir(rootfs, 0711); err != nil && !os.IsExist(err) {
			return err
		}
	}
	if err2 := mount.UnmountAll(rootfs, 0); err2 != nil {
		logrus.WithError(err2).Warn("failed to cleanup rootfs mount")
	}
	logrus.Debugf("carrierMain: unmount rootfs time cost: %d", (time.Now().Sub(timeStart))/time.Second)
	return nil
}
