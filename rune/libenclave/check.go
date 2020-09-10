package libenclave // import "github.com/opencontainers/runc/libenclave"

import (
	"fmt"
	"strings"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/devices"
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
	case configs.EnclaveHwIntelSgx:
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
	case configs.EnclaveHwIntelSgx:
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
	case configs.EnclaveHwIntelSgx:
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
