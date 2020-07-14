package v2

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	shim_config "github.com/alibaba/inclavare-containers/shim/config"
	"github.com/alibaba/inclavare-containers/shim/runtime/carrier"
	emptycarrier "github.com/alibaba/inclavare-containers/shim/runtime/carrier/empty"
	"github.com/alibaba/inclavare-containers/shim/runtime/carrier/graphene"
	"github.com/alibaba/inclavare-containers/shim/runtime/carrier/occlum"
	"github.com/alibaba/inclavare-containers/shim/runtime/config"
	signclient "github.com/alibaba/inclavare-containers/shim/runtime/signature/client"
	"github.com/alibaba/inclavare-containers/shim/runtime/v2/rune"
	"github.com/alibaba/inclavare-containers/shim/runtime/v2/rune/constants"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/pkg/process"
	taskAPI "github.com/containerd/containerd/runtime/v2/task"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// runE main flow.
func (s *service) carrierMain(req *taskAPI.CreateTaskRequest) (carrier.Carrier, error) {
	timeStart := time.Now()
	ts := time.Now()
	var err error
	var carr carrier.Carrier

	defer func() {
		carr.Cleanup()
		logrus.Debugf("carrierMain: total time cost: %d", (time.Now().Sub(ts))/time.Second)
	}()
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
		err = mountRootfs(req)
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

	unsignedEnclave, err := carr.BuildUnsignedEnclave(req, &carrier.BuildUnsignedEnclaveArgs{
		Bundle: req.Bundle,
	})
	if err != nil {
		return carr, err
	}

	commonArgs := carrier.CommonArgs{
		Enclave: unsignedEnclave,
		Config:  "", //TODO
	}
	signingMaterial, err := carr.GenerateSigningMaterial(req, &commonArgs)
	if err != nil {
		return carr, err
	}
	var signatureFile string
	if carrierKind != rune.Empty {
		//TODO: Retry on failture.
		var cfg shim_config.Config
		var publicKey, signature string
		if _, err := toml.DecodeFile(constants.ConfigurationPath, &cfg); err != nil {
			return carr, err
		}
		timeStart = time.Now()
		materialRealPath := signingMaterial
		if carrierKind == rune.Occlum {
			materialRealPath = filepath.Join(req.Bundle, signingMaterial)
		}
		if cfg.Signature.ServerAddress == "" {
			publicKey, signature, err = mockSign(materialRealPath)
			if err != nil {
				logrus.Errorf("carrierMain: mock sign failed. error: %++v", err)
				return carr, err
			}
			defer os.RemoveAll(path.Dir(publicKey))
		} else {
			publicKey, signature, err = remoteSign(fmt.Sprintf("%s/api/v1/signature",
				cfg.Signature.ServerAddress), materialRealPath)
			if err != nil {
				logrus.Errorf("carrierMain: get signature failed. server address: %s. error: %++v",
					cfg.Signature.ServerAddress, err)
				return carr, err
			}
			defer os.RemoveAll(path.Dir(publicKey))
		}
		logrus.Debugf("carrierMain: sign enclave time cost: %d", (time.Now().Sub(timeStart))/time.Second)
		defer os.RemoveAll(path.Dir(publicKey))
		commonArgs.Key = publicKey
		signatureFile = signature
	}
	signedEnclave, err := carr.CascadeEnclaveSignature(req, &carrier.CascadeEnclaveSignatureArgs{
		CommonArgs:      commonArgs,
		SigningMaterial: signingMaterial,
		Signature:       signatureFile,
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
	if value == rune.Occlum || value == rune.Graphene || value == rune.Empty || value == rune.Skeleton {
		found = true
		return
	}
	err = errors.Wrapf(rune.ErrorUnknownCarrier, "unexpected carrier kind: %v", value)
	return
}

func mockSign(signingMaterialFile string) (publicKeyFile, signatureFile string, err error) {
	dir, _ := ioutil.TempDir("/tmp", "signature-")
	privateKeyFile := filepath.Join(dir, "private_key.pem")
	publicKeyFile = filepath.Join(dir, "public_key.pem")
	signatureFile = filepath.Join(dir, "signature.dat")
	cmd := exec.Command("openssl", "genrsa", "-out", privateKeyFile, "-3", "3072")
	if _, err = cmd.Output(); err != nil {
		return
	}
	cmd = exec.Command("openssl", "rsa", "-in", privateKeyFile, "-pubout", "-out", publicKeyFile)
	if _, err = cmd.Output(); err != nil {
		return
	}
	cmd = exec.Command("openssl", "dgst", "-sha256", "-out", signatureFile, "-sign", privateKeyFile, "-keyform", "PEM", signingMaterialFile)
	if _, err = cmd.Output(); err != nil {
		return
	}
	return
}

func remoteSign(serverUrl, signingMaterial string) (publicKeyFile, signatureFile string, err error) {
	su, err := url.Parse(serverUrl)
	if err != nil {
		return
	}
	sigClient := signclient.NewClient(signclient.PKCS1, su)
	bytes, err := ioutil.ReadFile(signingMaterial)
	if err != nil {
		return
	}
	dir, err := ioutil.TempDir("/tmp", "signature-")
	if err != nil {
		return
	}
	signatureFile = filepath.Join(dir, "signature.dat")
	publicKeyFile = filepath.Join(dir, "public_key.pem")
	signature, publicKey, err := sigClient.Sign(bytes)
	if err := ioutil.WriteFile(signatureFile, signature, 0644); err != nil {
		return "", "", err
	}
	if err := ioutil.WriteFile(publicKeyFile, publicKey, 0644); err != nil {
		return "", "", err
	}
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
	return nil
}
