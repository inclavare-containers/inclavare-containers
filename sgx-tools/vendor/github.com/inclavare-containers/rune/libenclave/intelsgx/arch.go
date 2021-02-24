package intelsgx // import "github.com/inclavare-containers/rune/libenclave/intelsgx"

import (
	"fmt"
	"unsafe"
)

var (
	sgx1Supported           bool = false
	sgx2Supported           bool = false
	virtualizationSupported bool = false
	oversubSupported        bool = false
	miscSelectFeatures      uint32
	maxEnclaveSizeBits      uint32
)

const (
	SigStructLength                  = 1808
	EinittokenLength                 = 304
	TargetinfoLength                 = 512
	ReportLength                     = ReportBodyLength + 48
	ReportBodyLength                 = 384
	QuoteLength                      = QuoteHeaderLength + QuoteBodyLength + ReportBodyLength + 4
	QuoteHeaderLength                = 4
	QuoteBodyLength                  = 44
	NonceLength                      = 16
	SpidLength                       = 16
	AttestationSubscriptionKeyLength = 16
)

const (
	SgxEpidMaxQuoteLength  = 2048
	SgxEcdsaMinQuoteLength = 1020
)

const (
	attestationKeyIdentityLength = 256
	qeReportInfoLength           = 960
)

const (
	// EPID 2.0 - Anonymous
	sgxQuoteLibraryAlgorithmEpid = 0
	// Reserved
	sgxQuoteLibraryAlgorithmReseverd1 = 1
	// ECDSA-256-with-P-256 curve, Non - Anonymous
	sgxQuoteLibraryAlgorithmEcdsaP256 = 2
	// ECDSA-384-with-P-384 curve (Note: currently not supported), Non-Anonymous
	sgxQuoteLibraryAlgorithmEcdsaP384 = 3
	sgxQuoteLibraryAlgorithmMax       = 4
)

const (
	QuoteTypeEcdsa          = "ecdsa"
	QuoteTypeEpidUnlinkable = "epidUnlinkable"
	QuoteTypeEpidLinkable   = "epidLinkable"
)

type attestationKeyIdentity struct {
	Id             uint16    `struct:"uint16,little"`
	Version        uint16    `struct:"uint16,little"`
	MrsignerLength uint16    `struct:"uint16,little"`
	Mrsigner       [48]uint8 `struct:"[48]uint8"`
	ProdId         uint32    `struct:"uint32,little"`
	ExtendedProdId [16]uint8 `struct:"[16]uint8"`
	ConfigId       [64]uint8 `struct:"[64]uint8"`
	FamilyId       [16]uint8 `struct:"[16]uint8"`
	AlgorithmId    uint32    `struct:"uint32,little"`
}

type SigStruct struct {
	Header         [16]byte  `struct:"[16]byte"`
	Vendor         uint32    `struct:"uint32,little"`
	BuildYear      uint16    `struct:"uint16,little"`
	BuildMonth     uint8     `struct:"uint8"`
	BuildDay       uint8     `struct:"uint8"`
	Header2        [16]byte  `struct:"[16]byte"`
	SwDefined      uint32    `struct:"uint32,little"`
	_              [84]byte  `struct:"[84]byte"`
	Modulus        [384]byte `struct:"[384]byte"`
	Exponent       uint32    `struct:"uint32,little"`
	Signature      [384]byte `struct:"[384]byte"`
	MiscSelect     uint32    `struct:"uint32,little"`
	MiscMask       uint32    `struct:"uint32,little"`
	_              [4]byte   `struct:"[4]byte"`
	ISVFamilyId    [16]byte  `struct:"[16]byte"`
	Attributes     [16]byte  `struct:"[16]byte"`
	AttributesMask [16]byte  `struct:"[16]byte"`
	EnclaveHash    [32]byte  `struct:"[32]byte"`
	_              [16]byte  `struct:"[16]byte"`
	ISVExtProdId   [16]byte  `struct:"[16]byte"`
	ISVProdId      uint16    `struct:"uint16,little"`
	ISVSvn         uint16    `struct:"uint16,little"`
	_              [12]byte  `struct:"[12]byte"`
	Q1             [384]byte `struct:"[384]byte"`
	Q2             [384]byte `struct:"[384]byte"`
}

type Einittoken struct {
	Valid              uint32   `struct:"uint32,little"`
	_                  [44]byte `struct:"[44]byte"`
	Attributes         [16]byte `struct:"[16]byte"`
	MrEnclave          [32]byte `struct:"[32]byte"`
	_                  [32]byte `struct:"[32]byte"`
	MrSigner           [32]byte `struct:"[32]byte"`
	_                  [32]byte `struct:"[32]byte"`
	CpuSvnLe           [16]byte `struct:"[16]byte"`
	ISVProdIdLe        uint16   `struct:"uint16"`
	ISVSvnLe           uint16   `struct:"uint16"`
	_                  [24]byte `struct:"[24]byte"`
	MaskedMiscSelectLe uint32   `struct:"uint32"`
	MaskedAttributesLe [16]byte `struct:"[16]byte"`
	KeyId              [32]byte `struct:"[32]byte"`
	Mac                [16]byte `struct:"[16]byte"`
}

type Targetinfo struct {
	Measurement   [32]byte  `struct:"[32]byte"`
	Attributes    [16]byte  `struct:"[16]byte"`
	CetAttributes uint8     `struct:"uint8"`
	_             uint8     `struct:"uint8"`
	ConfigSvn     uint16    `struct:"uint16"`
	MiscSelect    uint32    `struct:"uint32"`
	_             [8]byte   `struct:"[8]byte"`
	ConfigId      [64]byte  `struct:"[64]byte"`
	_             [384]byte `struct:"[384]byte"`
}

type Report struct {
	ReportBody
	Keyid [32]byte `struct:"[32]byte"`
	Mac   [16]byte `struct:"[16]byte"`
}

type ReportBody struct {
	CpuSvn       [16]byte `struct:"[16]byte"`
	MiscSelect   uint32   `struct:"uint32"`
	_            [12]byte `struct:"[12]byte"`
	IsvExtProdId [16]byte `struct:"[16]byte"`
	Attributes   [16]byte `struct:"[16]byte"`
	MrEnclave    [32]byte `struct:"[32]byte"`
	_            [32]byte `struct:"[32]byte"`
	MrSigner     [32]byte `struct:"[32]byte"`
	_            [32]byte `struct:"[32]byte"`
	ConfigId     [64]byte `struct:"[64]byte"`
	IsvProdId    uint16   `struct:"uint16"`
	IsvSvn       uint16   `struct:"uint16"`
	ConfigSvn    uint16   `struct:"uint16"`
	_            [42]byte `struct:"[42]byte"`
	IsvFamilyId  [16]byte `struct:"[16]byte"`
	ReportData   [64]byte `struct:"[64]byte"`
}

type Quote struct {
	QuoteHeader
	QuoteBody [44]byte `struct:"[44]byte"`
	ReportBody
	SigLen uint32 `struct:"uint32"`
}

const (
	QuoteSignatureTypeUnlinkable = iota
	QuoteSignatureTypeLinkable
	QuoteSignatureTypeEcdsaP256
	QuoteSignatureTypeEcdsaP384
)

const (
	QuoteVersion2 = 2
	QuoteVersion3 = 3
)

type QuoteHeader struct {
	Version       uint16 `struct:"uint16"`
	SignatureType uint16 `struct:"uint16"`
}

type QuoteBodyV2 struct {
	Gid       uint32   `struct:"uint32"`
	ISVSvnQe  uint16   `struct:"uint16"`
	ISVSvnPce uint16   `struct:"uint16"`
	_         [4]byte  `struct:"[4]byte"`
	Basename  [32]byte `struct:"[32]byte"`
}

type QuoteBodyV3 struct {
	TeeType    uint16    `struct:"uint16"`
	_          uint16    `struct:"uint16"`
	QeSvn      uint16    `struct:"uint16"`
	PceSvn     uint16    `struct:"uint16"`
	QeVendorId [16]uint8 `struct:"[16]uint8"`
	UserData   [20]uint8 `struct:"[20]uint8"`
}

// Check whether CPUs support SGX or not
func IsSgxSupported() bool {
	_, ebx, _, _ := cpuid(cpuidExtendedFeatureFlags, 0)
	if (ebx & 0x4) == 0x0 {
		return false
	}

	return true
}

func GetSgxFeatures() {
	// cpuidSgxFeature leaf is supported only if cpuidExtendedFeatureFlags leaf supported
	if !IsSgxSupported() {
		return
	}

	eax, ebx, _, edx := cpuid(cpuidSgxFeature, sgxCapabilties)
	if (eax & 0x1) != 0 {
		sgx1Supported = true
	}

	if (eax & 0x2) != 0 {
		sgx2Supported = true
	}

	if (eax & 0x20) != 0 {
		virtualizationSupported = true
	}

	if (eax & 0x40) != 0 {
		oversubSupported = true
	}

	miscSelectFeatures = ebx

	bit := 32 << (^uint(0) >> 63)
	if bit == 64 {
		maxEnclaveSizeBits = (edx & 0xff00) >> 8
	} else {
		maxEnclaveSizeBits = edx & 0xff
	}
}

// Check whether Intel SGX supports the collection of SGX1 leaf functions
func IsSGX1FunctionsSupported() bool {
	return sgx1Supported
}

// Check whether Intel SGX supports the collection of SGX2 leaf functions
func IsSGX2FunctionsSupported() bool {
	return sgx2Supported
}

// Check whether Intel SGX supports ENCLV instructions EINCVIRTCHILD, EDECVIRTCHILD, and ESETCONTEXT
func IsVirtualizationSupported() bool {
	return virtualizationSupported
}

// Check whether Intel SGX supports ENCLS instructions ETRACKC, ERDINFO, ELDBC, and ELDUC
func IsOversubSupported() bool {
	return oversubSupported
}

// Get the bit vector of supported extended SGX features
func GetExtendedSGXFeatures() uint32 {
	return miscSelectFeatures
}

// Get the max enclave size value
func GetMaxEnclaveSizeBits() uint32 {
	return maxEnclaveSizeBits
}

// Check whether the enclave is a product enclave or not
func IsProductEnclave(reportBody ReportBody) (bool, error) {
	if unsafe.Sizeof(reportBody) != ReportBodyLength {
		return false, fmt.Errorf("len(report) is not %d, but %d", ReportBodyLength, unsafe.Sizeof(reportBody))
	}

	if reportBody.Attributes[0]&0x02 != 0x0 {
		return false, nil
	}

	return false, nil
}
