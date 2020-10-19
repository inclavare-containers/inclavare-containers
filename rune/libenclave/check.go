package libenclave // import "github.com/inclavare-containers/rune/libenclave"

import (
	"fmt"
	"os"
	"strings"

	"github.com/inclavare-containers/rune/libenclave/attestation/sgx"
	enclaveConfigs "github.com/inclavare-containers/rune/libenclave/configs"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/devices"
	libenclaveUtils "github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"

	"golang.org/x/sys/unix"
)

func createLibenclaveMount(cwd string) *configs.Mount {
	return &configs.Mount{
		Device:           "bind",
		Source:           "/var/run/aesmd",
		Destination:      "/var/run/aesmd",
		Flags:            unix.MS_BIND | unix.MS_REC,
		PropagationFlags: []int{unix.MS_PRIVATE | unix.MS_REC},
	}
}

func CreateLibenclaveMount(cwd string, config *configs.Config) {
	aesmedMounted := false
	for _, m := range config.Mounts {
		if strings.EqualFold(m.Destination, "/var/run/aesmd") || strings.EqualFold(m.Destination, "/run/aesmd") {
			aesmedMounted = true
			break
		}
	}
	if aesmedMounted != true {
		config.Mounts = append(config.Mounts, createLibenclaveMount(cwd))
	}
}

func CreateEnclaveCgroupConfig(devices *[]*configs.Device, etype string) {
	createEnclaveDevices(*devices, etype, func(dev *configs.Device) {
		dev.Permissions = "rwm"
		dev.Allow = true
		*devices = append(*devices, dev)
	})
}

// Determine whether the device is a Intel SGX enclave device
func intelSgxDev(device *configs.Device) (*configs.Device, error) {
	dev, err := devices.DeviceFromPath(device.Path, "rwm")
	if err != nil {
		return nil, err
	}

	if dev.Type == 'c' && dev.Major == 10 {
		return dev, nil
	}

	return nil, fmt.Errorf("%s is not a SGX enclave device", dev.Path)
}

func createEnclaveDevices(devs []*configs.Device, etype string, fn func(dev *configs.Device)) {
	var configuredDevs []string
	// Retrieve the configured enclave devices
	onMatchEnclaveDevice(devs, genEnclavePathTemplate(etype), etype, func(n string, i int) {
		configuredDevs = append(configuredDevs, n)
	})

	if len(configuredDevs) != 0 {
		for _, d := range configuredDevs {
			dev, err := devices.DeviceFromPath(d, "rwm")
			if err != nil {
				logrus.Debugf("the configured enclave device %s not exist", dev.Path)
				continue
			}

			logrus.Debugf("the enclave device %s configured", dev.Path)
		}
	}

	// Filter out the configured enclave devices
	exclusiveDevs := genEnclaveDeviceTemplate(etype)

	onMatchEnclaveDevice(exclusiveDevs, configuredDevs, etype, func(n string, i int) {
		exclusiveDevs = append(exclusiveDevs[:i], exclusiveDevs[i+1:]...)
	})

	// Create the enclave devices not explicitly specified
	for _, d := range exclusiveDevs {
		dev, err := intelSgxDev(d)
		if err != nil {
			continue
		}
		if !containEnclaveDevice(devs, dev.Path) {
			fn(dev)
		}
	}
}

func onMatchEnclaveDevice(devices []*configs.Device, names []string, etype string, fn func(n string, i int)) {
	switch etype {
	case enclaveConfigs.EnclaveHwIntelSgx:
		for _, n := range names {
			for i, dev := range devices {
				if dev.Path == n {
					fn(n, i)
				}
			}
		}
	}
}

func genEnclaveDeviceTemplate(etype string) []*configs.Device {
	switch etype {
	case enclaveConfigs.EnclaveHwIntelSgx:
		return []*configs.Device{
			&configs.Device{
				Type:  'c',
				Path:  "/dev/isgx",
				Major: 10,
			},
			&configs.Device{
				Type:  'c',
				Path:  "/dev/sgx/enclave",
				Major: 10,
			},
			&configs.Device{
				Type:  'c',
				Path:  "/dev/gsgx",
				Major: 10,
			},
		}
	default:
		return nil
	}
}

func containEnclaveDevice(devices []*configs.Device, s string) bool {
	for _, c := range devices {
		if c.Path == s {
			return true
		}
	}
	return false
}

func genEnclavePathTemplate(etype string) []string {
	switch etype {
	case enclaveConfigs.EnclaveHwIntelSgx:
		return []string{"/dev/isgx", "/dev/sgx/enclave", "/dev/gsgx"}
	default:
		return nil
	}
}

func CreateEnclaveDeviceConfig(devices *[]*configs.Device, etype string) {
	createEnclaveDevices(*devices, etype, func(dev *configs.Device) {
		dev.FileMode = 0666
		dev.Uid = 0
		dev.Gid = 0
		*devices = append(*devices, dev)
	})
}

func CreateEnclaveConfig(spec *specs.Spec, config *configs.Config) *enclaveConfigs.EnclaveConfig {
	filterOut := func(env *[]string, name string) string {
		for i, pair := range *env {
			p := strings.SplitN(pair, "=", 2)
			if p[0] != name {
				continue
			}

			// The related environment variables are only used to pass parameters
			// without the necessity of being inherited to container.
			*env = append((*env)[:i], (*env)[i+1:]...)

			if len(p[1]) > 1 {
				return p[1]
			}

			return ""
		}

		return ""
	}

	env := &spec.Process.Env
	etype := filterOut(env, "ENCLAVE_TYPE")
	if etype == "" {
		etype = libenclaveUtils.SearchLabels(config.Labels, "enclave.type")
		if etype == "" {
			etype = enclaveConfigs.EnclaveHwDefault
		}
	}

	// rune will work as runc because enclave is not configured.
	if etype == "" {
		return nil
	}

	path := filterOut(env, "ENCLAVE_RUNTIME_PATH")
	if path == "" {
		path = libenclaveUtils.SearchLabels(config.Labels, "enclave.runtime.path")
	}

	args := filterOut(env, "ENCLAVE_RUNTIME_ARGS")
	if args == "" {
		args = libenclaveUtils.SearchLabels(config.Labels, "enclave.runtime.args")
	}
	if args != "" {
		a := strings.Split(args, ",")
		args = strings.Join(a, " ")
	}

	raType := filterOut(env, "ENCLAVE_RA_TYPE")
	if raType == "" {
		raType = libenclaveUtils.SearchLabels(config.Labels, "enclave.attestation.ra_type")
	}

	var enclaveRaType, sgxEnclaveType, raEpidIsLinkable uint32 = sgx.UnknownRaType, sgx.InvalidEnclaveType, intelsgx.InvalidQuoteSignatureType
	var raEpidSpid, raEpidSubscriptionKey string
	if raType != "" {
		if strings.EqualFold(raType, "EPID") {
			enclaveRaType = sgx.EPID
		} else if strings.EqualFold(raType, "DCAP") {
			enclaveRaType = sgx.DCAP
		}

		isProductEnclave := filterOut(env, "ENCLAVE_IS_PRODUCT_ENCLAVE")
		if isProductEnclave == "" {
			isProductEnclave = libenclaveUtils.SearchLabels(config.Labels, "enclave.is_product_enclave")
		}
		if strings.EqualFold(isProductEnclave, "false") {
			sgxEnclaveType = sgx.DebugEnclave
		} else if strings.EqualFold(isProductEnclave, "true") {
			sgxEnclaveType = sgx.ProductEnclave
		}

		raEpidSpid = filterOut(env, "ENCLAVE_RA_EPID_SPID")
		if raEpidSpid == "" {
			raEpidSpid = libenclaveUtils.SearchLabels(config.Labels, "enclave.attestation.ra_epid_spid")
		}

		raEpidSubscriptionKey = filterOut(env, "ENCLAVE_RA_EPID_SUB_KEY")
		if raEpidSubscriptionKey == "" {
			raEpidSubscriptionKey = libenclaveUtils.SearchLabels(config.Labels, "enclave.attestation.ra_epid_subscription_key")
		}

		linkable := filterOut(env, "ENCLAVE_RA_EPID_IS_LINKABLE")
		if linkable == "" {
			linkable = libenclaveUtils.SearchLabels(config.Labels, "enclave.attestation.ra_epid_is_linkable")
		}
		if strings.EqualFold(linkable, "true") {
			raEpidIsLinkable = intelsgx.QuoteSignatureTypeLinkable
		} else if strings.EqualFold(linkable, "false") {
			raEpidIsLinkable = intelsgx.QuoteSignatureTypeUnlinkable
		}
	}

	enclave := &enclaveConfigs.Enclave{
		Type:                  etype,
		Path:                  path,
		Args:                  args,
		IsProductEnclave:      sgxEnclaveType,
		RaType:                enclaveRaType,
		RaEpidSpid:            raEpidSpid,
		RaEpidSubscriptionKey: raEpidSubscriptionKey,
		RaEpidIsLinkable:      raEpidIsLinkable,
	}
	enclaveConfig := &enclaveConfigs.EnclaveConfig{
		Enclave: enclave,
	}
	return enclaveConfig
}

func ValidateEnclave(config *enclaveConfigs.EnclaveConfig) error {
	if config.Enclave == nil {
		return nil
	}

	if !IsEnclaveEnabled(config.Enclave) {
		return fmt.Errorf("Enclave hardware type (%v) is not supported", config.Enclave.Type)
	}

	if config.Enclave.Path == "" {
		return fmt.Errorf("enclave runtime path is not configured")
	}

	if _, err := os.Stat(config.Enclave.Path); err != nil {
		return err
	}

	if config.Enclave.RaType != sgx.UnknownRaType {
		if config.Enclave.IsProductEnclave == sgx.InvalidEnclaveType {
			return fmt.Errorf("Unsupported enclave.is_product_enclave Configuration!\n")
		}

		if config.Enclave.RaEpidSpid == "" {
			return fmt.Errorf("The enclave.attestation.ra_epid_spid Configuration isn't set!\n")
		}

		if config.Enclave.RaEpidSubscriptionKey == "" {
			return fmt.Errorf("The enclave.attestation.ra_epid_subscription_key Configuration isn't set!\n")
		}

		if config.Enclave.RaEpidIsLinkable == intelsgx.InvalidQuoteSignatureType {
			return fmt.Errorf("Unsupported enclave.attestation.ra_epid_is_linkable Configuration!\n")
		}
	}

	return nil
}
