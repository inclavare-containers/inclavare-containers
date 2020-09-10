package intelsgx // import "github.com/opencontainers/runc/libenclave/intelsgx"

/*
#include <stdlib.h>
#include <unistd.h>

static void cpuid(__uint32_t leaf, __uint32_t sub_leaf,
		  __uint32_t *eax, __uint32_t *ebx,
		  __uint32_t *ecx, __uint32_t *edx)
{
        asm volatile("cpuid"
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "0"(leaf), "2"(sub_leaf)
                     : "memory");
}
*/
import "C"
import "unsafe"

// CPUID leafs
const (
	cpuidExtendedFeatureFlags = 0x7
	cpuidSgxFeature           = 0x12
)

// CPUID leaf 0x12 sub-leafs
const (
	sgxCapabilties    = 0
	sgxAttributes     = 1
	sgxEpcBaseSection = 2
	maxSgxEpcSections = 8
)

func cpuid(leaf uint32, subLeaf uint32) (uint32, uint32, uint32, uint32) {
	var (
		eax uint32
		ebx uint32
		ecx uint32
		edx uint32
	)

	C.cpuid(C.uint(leaf), C.uint(subLeaf), (*C.uint)(unsafe.Pointer(&eax)),
		(*C.uint)(unsafe.Pointer(&ebx)), (*C.uint)(unsafe.Pointer(&ecx)),
		(*C.uint)(unsafe.Pointer(&edx)))

	return eax, ebx, ecx, edx
}
