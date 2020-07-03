package intelsgx // import "github.com/opencontainers/runc/libenclave/intelsgx"

type SgxEpcSection struct {
	PhysicalAddress uint64
	Size            uint64
}

// Get each Enclave Page Cache Size
func GetEpcSections() []SgxEpcSection {
	sections := []SgxEpcSection{}

	for i := 0; i < maxSgxEpcSections; i++ {
		eax, ebx, ecx, edx := cpuid(cpuidSgxFeature, uint32(sgxEpcBaseSection+i))

		if (eax & 0xf) == 0x0 {
			break
		}

		pa := ((uint64)(ebx&0xfffff) << 32) + (uint64)(eax&0xfffff000)
		sz := ((uint64)(edx&0xfffff) << 32) + (uint64)(ecx&0xfffff000)

		sections = append(sections, SgxEpcSection{pa, sz})
	}

	return sections
}

// Get the total Enclave Page Cache Size of CPUs
func GetEpcSize() uint64 {
	sections := GetEpcSections()

	var epcSize uint64 = 0

	for _, s := range sections {
		epcSize += s.Size
	}

	return epcSize
}
