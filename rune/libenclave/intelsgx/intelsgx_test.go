package intelsgx

import (
	"fmt"
	"testing"
)

func launchControl_test() {
	if IsSGXLaunchControlSupported() {
		fmt.Printf("1: SGX Launch Control is supported!\n")
	} else {
		fmt.Printf("1: SGX Launch Control isn't supported!\n")
	}
}

func arch_test() {
	if IsSGX1FunctionsSupported() {
		fmt.Printf("2: SGX1 function is supported!\n")
	} else {
		fmt.Printf("2: SGX1 function isn't supported!\n")
	}

	if IsSGX2FunctionsSupported() {
		fmt.Printf("3: SGX2 function is supported!\n")
	} else {
		fmt.Printf("3: SGX2 function isn't supported!\n")
	}

	maxEnclaveSizeBits := GetMaxEnclaveSizeBits()
	fmt.Printf("4: The Max Enclave Size Bits Supported = 0x%x\n", maxEnclaveSizeBits)

	bit_vector := GetExtendedSGXFeatures()
	fmt.Printf("5: The bit vector of Extended SGX Features = 0x%x\n", bit_vector)
}

func secs_test() {
	eax, ebx, ecx, edx := getSecsAttributes()
	fmt.Printf("6: the valid bits: 0-31 bits = 0x%x, 32-63 bits = %x, 64-95 bits = 0x%x, 96-127 bits = 0x%x\n", eax, ebx, ecx, edx)
}

func TestSgxArch(t *testing.T) {
	fmt.Printf("SGX Arch Test start!\n")

	if IsSgxSupported() {
		fmt.Printf("0: SGX is supported!\n")
	} else {
		fmt.Printf("0: SGX isn't supported!\n")
		fmt.Printf("SGX Arch Test End!\n")
		return
	}

	GetSgxLaunchControl()
	launchControl_test()

	GetSgxFeatures()
	arch_test()

	secs_test()

	fmt.Printf("SGX Arch Test end!\n")
}
