package intelsgx // import "github.com/opencontainers/runc/libenclave/intelsgx"

var (
	sgxLaunchControlSupported bool = false
)

func GetSgxLaunchControl() {
	_, _, ecx, _ := cpuid(cpuidExtendedFeatureFlags, 0)
	if (ecx & 0x40000000) != 0 {
		sgxLaunchControlSupported = true
	}
}

// Check whether Intel SGX supports Launch Control or not
func IsSGXLaunchControlSupported() bool {
	return sgxLaunchControlSupported
}
