package intelsgx // import "github.com/opencontainers/runc/libenclave/intelsgx"

func getSecsAttributes() (uint32, uint32, uint32, uint32) {
	eax, ebx, ecx, edx := cpuid_low(cpuidSgxFeature, sgxAttributes)
	return eax, ebx, ecx, edx
}
