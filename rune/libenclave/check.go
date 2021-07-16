package libenclave // import "github.com/inclavare-containers/rune/libenclave"

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

func CreateLibenclaveMount(cwd string, config *configs.Config, etype string) {
	if etype != enclaveConfigs.EnclaveTypeIntelSgx {
		return
	}

	_, err := os.Stat("/var/run/aesmd")
	if os.IsNotExist(err) {
		return
	}

	for _, m := range config.Mounts {
		if strings.EqualFold(m.Destination, "/var/run/aesmd") || strings.EqualFold(m.Destination, "/run/aesmd") {
			return
		}
	}

	config.Mounts = append(config.Mounts, createLibenclaveMount(cwd))
}

func createLibenclaveEPMMount(cwd string) *configs.Mount {
	return &configs.Mount{
		Device:           "bind",
		Source:           "/var/run/epm",
		Destination:      "/var/run/epm",
		Flags:            unix.MS_BIND | unix.MS_REC,
		PropagationFlags: []int{unix.MS_PRIVATE | unix.MS_REC},
	}
}

func CreateLibenclaveEPMMount(cwd string, config *configs.Config, etype string) {
	if etype != enclaveConfigs.EnclaveTypeIntelSgx {
		return
	}

	_, err := os.Stat("/var/run/epm")
	if os.IsNotExist(err) {
		return
	}

	for _, m := range config.Mounts {
		if strings.EqualFold(m.Destination, "/var/run/epm") {
			return
		}
	}

	config.Mounts = append(config.Mounts, createLibenclaveEPMMount(cwd))
}

func CreateEnclaveCgroupConfig(rules *[]*devices.Rule, devices []*devices.Device) {
	for _, d := range devices {
		dev, err := enclaveMiscDev(d)
		if err != nil {
			continue
		}
		dev.Rule.Permissions = "rwm"
		dev.Rule.Allow = true
		*rules = append(*rules, &dev.Rule)
	}
}

// Determine whether the device is a Intel SGX enclave or AWS Nitro Enclaves device
func enclaveMiscDev(device *devices.Device) (*devices.Device, error) {
	var path string
	var err error
	if device.Type == 'l' {
		path, err = filepath.EvalSymlinks(device.Path)
		if err != nil {
			return nil, err
		}
	} else {
		path = device.Path
	}

	dev, err := devices.DeviceFromPath(path, "rwm")
	if err != nil {
		return nil, err
	}

	if dev.Type == 'c' && dev.Major == 10 {
		// The SGX device used by the DCAP OOT driver and in-tree driver（>=v1.41) is /dev/sgx_enclave.
		// However, Intel SGX SDK does not support this path. Instead, it provides a udev rule creating
		// the symbolic link /dev/sgx/enclave pointing to /dev/sgx_enclave. To support this behavior,
		// rune identifies whether the enclave device is a symbolic link pointing to the actual sgx device,
		// and then mount the sgx device using the path of symbolic link.
		if device.Type == 'l' {
			dev.Path = device.Path
		}
		return dev, nil
	}

	return nil, fmt.Errorf("%s is not a SGX enclave device", dev.Path)
}

func createEnclaveDevices(devs []*devices.Device, etype string, fn func(dev *devices.Device)) {
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
		dev, err := enclaveMiscDev(d)
		if err != nil {
			continue
		}
		if !containEnclaveDevice(devs, dev.Path) {
			fn(dev)
		}
	}
}

func onMatchEnclaveDevice(devices []*devices.Device, names []string, etype string, fn func(n string, i int)) {
	for _, n := range names {
		for i, dev := range devices {
			if dev.Path == n {
				fn(n, i)
			}
		}
	}
}

func genEnclaveDeviceTemplate(etype string) []*devices.Device {
	switch etype {
	case enclaveConfigs.EnclaveTypeIntelSgx:
		return []*devices.Device{
			&devices.Device{
				Rule: devices.Rule{
					Type:  'c',
					Major: 10,
				},
				Path: "/dev/sgx_enclave",
			},
			&devices.Device{
				Rule: devices.Rule{
					Type:  'c',
					Major: 10,
				},
				Path: "/dev/sgx/enclave",
			},
			&devices.Device{
				Rule: devices.Rule{
					Type:  'l',
					Major: 10,
				},
				Path: "/dev/sgx/enclave",
			},
			&devices.Device{
				Rule: devices.Rule{
					Type:  'c',
					Major: 10,
				},
				Path: "/dev/sgx_provision",
			},
			&devices.Device{
				Rule: devices.Rule{
					Type:  'c',
					Major: 10,
				},
				Path: "/dev/sgx/provision",
			},
			&devices.Device{
				Rule: devices.Rule{
					Type:  'l',
					Major: 10,
				},
				Path: "/dev/sgx/provision",
			},
			&devices.Device{
				Rule: devices.Rule{
					Type:  'c',
					Major: 10,
				},
				Path: "/dev/isgx",
			},
			&devices.Device{
				Rule: devices.Rule{
					Type:  'c',
					Major: 10,
				},
				Path: "/dev/gsgx",
			},
		}
	case enclaveConfigs.EnclaveTypeAwsNitroEnclaves:
		return []*devices.Device{
			&devices.Device{
				Rule: devices.Rule{
					Type:  'c',
					Major: 10,
				},
				Path: "/dev/nitro_enclaves",
			},
		}
	case enclaveConfigs.EnclaveTypeJailHouse:
		return []*devices.Device{
			&devices.Device{
				Rule: devices.Rule{
					Type:  'c',
					Major: 10,
				},
				Path: "/dev/jailhouse",
			},
		}
	default:
		return nil
	}
}

func containEnclaveDevice(devices []*devices.Device, s string) bool {
	for _, c := range devices {
		if c.Path == s {
			return true
		}
	}
	return false
}

func genEnclavePathTemplate(etype string) []string {
	switch etype {
	case enclaveConfigs.EnclaveTypeIntelSgx:
		return []string{"/dev/sgx_enclave", "/dev/sgx/enclave", "/dev/sgx_provision", "/dev/sgx/provision", "/dev/isgx", "/dev/gsgx"}
	case enclaveConfigs.EnclaveTypeAwsNitroEnclaves:
		return []string{"/dev/nitro_enclaves"}
	case enclaveConfigs.EnclaveTypeJailHouse:
		return []string{"/dev/jailhouse"}
	default:
		return nil
	}
}

func CreateEnclaveDeviceConfig(device *[]*devices.Device, etype string) {
	createEnclaveDevices(*device, etype, func(dev *devices.Device) {
		dev.Uid = 0
		dev.Gid = 0
		*device = append(*device, dev)
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
			etype = enclaveConfigs.EnclaveTypeNone
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

	logLevel := filterOut(env, "ENCLAVE_RUNTIME_LOGLEVEL")
	if logLevel == "" {
		logLevel = libenclaveUtils.SearchLabels(config.Labels, "enclave.runtime.loglevel")
	}

	raType := filterOut(env, "ENCLAVE_RA_TYPE")
	if raType == "" {
		raType = libenclaveUtils.SearchLabels(config.Labels, "enclave.attestation.ra_type")
	}

	enclaveRaType := ""
	if strings.EqualFold(raType, intelsgx.QuoteTypeEpidUnlinkable) || strings.EqualFold(raType, intelsgx.QuoteTypeEpidLinkable) || strings.EqualFold(raType, intelsgx.QuoteTypeEcdsa) {
		enclaveRaType = raType
	}

	raEpidSpid := filterOut(env, "ENCLAVE_RA_EPID_SPID")
	if raEpidSpid == "" {
		raEpidSpid = libenclaveUtils.SearchLabels(config.Labels, "enclave.attestation.ra_epid_spid")
	}

	raEpidSubscriptionKey := filterOut(env, "ENCLAVE_RA_EPID_SUB_KEY")
	if raEpidSubscriptionKey == "" {
		raEpidSubscriptionKey = libenclaveUtils.SearchLabels(config.Labels, "enclave.attestation.ra_epid_subscription_key")
	}

	enclave := &enclaveConfigs.Enclave{
		Type:                  etype,
		Path:                  path,
		Args:                  args,
		LogLevel:              logLevel,
		RaType:                enclaveRaType,
		RaEpidSpid:            raEpidSpid,
		RaEpidSubscriptionKey: raEpidSubscriptionKey,
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

	IsValidLogLevel := false
	for _, v := range enclaveConfigs.LogLevelArray {
		if v == config.Enclave.LogLevel {
			IsValidLogLevel = true
			break
		}
	}
	if !IsValidLogLevel {
		logrus.Debugf("Invalid Enclave Runtime LogLevel")
		config.Enclave.LogLevel = enclaveConfigs.DefaultLogLevel
		logrus.Debugf("Use default LogLevel: %s", enclaveConfigs.DefaultLogLevel)
	}

	if strings.EqualFold(config.Enclave.RaType, intelsgx.QuoteTypeEpidUnlinkable) || strings.EqualFold(config.Enclave.RaType, intelsgx.QuoteTypeEpidLinkable) {
		if config.Enclave.RaEpidSpid == "" {
			return fmt.Errorf("The enclave.attestation.ra_epid_spid Configuration isn't set!\n")
		}

		if config.Enclave.RaEpidSubscriptionKey == "" {
			return fmt.Errorf("The enclave.attestation.ra_epid_subscription_key Configuration isn't set!\n")
		}
	}

	return nil
}
