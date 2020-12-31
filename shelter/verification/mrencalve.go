package verification

/*
//#cgo CFLAGS: -I/home/yl/work/linux-sgx/external/dcap_source/prebuilt/openssl/inc/openssl -I/usr/include/openssl
//#cgo LDFLAGS: -L/usr/lib  -lssl -lcrypto
#cgo CFLAGS:  -I/usr/include/openssl
#cgo LDFLAGS:  -lcrypto

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include "opensslevp.h"
*/
import "C"
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/go-restruct/restruct"
	"io"
	"os"
	"unsafe"
)

const (
	SGX_PAGE_TYPE_SECS = iota
	SGX_PAGE_TYPE_TCS
	SGX_PAGE_TYPE_REG
	SGX_PAGE_TYPE_VA
	SGX_PAGE_TYPE_TRIM
)

const (
	SGX_SECINFO_R    uint64 = 1
	SGX_SECINFO_W    uint64 = 2
	SGX_SECINFO_X    uint64 = 4
	SGX_SECINFO_SECS uint64 = (SGX_PAGE_TYPE_SECS << 8) //0x000
	SGX_SECINFO_TCS  uint64 = (SGX_PAGE_TYPE_TCS << 8)  //0x100
	SGX_SECINFO_REG  uint64 = (SGX_PAGE_TYPE_REG << 8)  //0x200
	SGX_SECINFO_VA   uint64 = (SGX_PAGE_TYPE_VA << 8)
	SGX_SECINFO_TRIM uint64 = (SGX_PAGE_TYPE_TRIM << 8)
)

const (
	MRECREATE = 0x0045544145524345
	MREADD    = 0x0000000044444145
	MREEXTEND = 0x00444E4554584545
)

const (
	MRENCALVE_HASH_SIZE = 32
	STD_PAGE_SIZE       = 0x1000
	SIGSTRUCT_SIZE      = 1808
)

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

type SgxTCS struct {
	state         uint64     `struct:"uint64,little"`
	flags         uint64     `struct:"uint64,little"`
	ssa_offset    uint64     `struct:"uint64,little"`
	ssa_index     uint32     `struct:"uint32,little"`
	nr_ssa_frames uint32     `struct:"uint32,little"`
	entry_offset  uint64     `struct:"uint64,little"`
	exit_addr     uint64     `struct:"uint64,little"`
	fs_offset     uint64     `struct:"uint64,little"`
	gs_offset     uint64     `struct:"uint64,little"`
	fs_limit      uint32     `struct:"uint32,little"`
	gs_limit      uint32     `struct:"uint32,little"`
	reserved      [4024]byte `struct:"[4024]byte"`
}

type mrecreate struct {
	tag      uint64   `struct:"uint64,little"`
	ssasize  int32    `struct:"int32,little"`
	size     uint64   `struct:"uint64,little"`
	Reserved [44]byte `struct:"[4024]byte"`
}

type mreadd struct {
	tag      uint64   `struct:"uint64,little"`
	offset   uint64   `struct:"uint64,little"`
	flags    uint64   `struct:"uint64,little"`
	reserved [40]byte `struct:"[40]byte"`
}

type mreextend struct {
	tag      uint64   `struct:"uint64,little"`
	offset   uint64   `struct:"uint64,little"`
	reserved [48]byte `struct:"[48]byte"`
}

func GoMemSet(s unsafe.Pointer, c byte, n uint) {
	ptr := uintptr(s)
	var i uint
	for i = 0; i < n; i++ {
		pByte := (*byte)(unsafe.Pointer(ptr + uintptr(i)))
		*pByte = c
	}
}

func MovePointer(s unsafe.Pointer, n uint) (p unsafe.Pointer) {
	ptr := unsafe.Pointer(uintptr(s) + uintptr(n))
	return ptr
}

func mrenclave_update(ctx *C.EVP_MD_CTX, data unsafe.Pointer) bool {

	if ret := C.X_EVP_DigestUpdate(ctx, data, 64); ret == 0 {
		fmt.Errorf("Digest update failed with ret %s.\n", ret)
		return false
	}
	return true
}

func mrenclave_commit(ctx *C.EVP_MD_CTX, mrenclave unsafe.Pointer) bool {
	var ssize uint
	if 1 != C.X_EVP_DigestFinal_ex(ctx, (*C.uchar)(mrenclave), (*C.uint)(unsafe.Pointer(&ssize))) {
		fmt.Errorf("Digest commit failed.\n")
		return false
	}

	if ssize != 32 {
		fmt.Errorf("Invalid digest size %d\n", ssize)
		return false
	}
	return true
}

func mrenclave_ecreate(ctx *C.EVP_MD_CTX, blob_size uint64, miscselect uint32, xfrm uint64, ssa_frame_size unsafe.Pointer, encl_size uint64) bool {
	//var encl_size uint64
	var ssasize uint32
	//for encl_size = 0x1000; encl_size < blob_size; encl_size = encl_size << 1 {
	//	fmt.Printf("encl_size is 0x%x, blob_size is 0x%x \n", encl_size, blob_size)
	//}

	buffer := bytes.NewBuffer([]byte{})

	err := binary.Write(buffer, binary.LittleEndian, uint64(MRECREATE))
	if err != nil {
		fmt.Errorf("MRECREATE write error.\n")
	}
	ssasize = (uint32)(C.sgx_calc_ssaframesize((C.uint32_t)(miscselect), (C.uint64_t)(xfrm)))
	err = binary.Write(buffer, binary.LittleEndian, uint32(ssasize))
	if err != nil {
		fmt.Errorf("ssasize write error.\n")
	}
	err = binary.Write(buffer, binary.LittleEndian, uint64(encl_size))
	if err != nil {
		fmt.Errorf("encl_size write error.\n")
	}
	var padding = [44]byte{0}
	err = binary.Write(buffer, binary.LittleEndian, padding)
	if err != nil {
		fmt.Errorf("padding write error.\n")
	}

	*(*uint32)(ssa_frame_size) = ssasize

	if 1 != C.X_EVP_DigestInit_ex(ctx, C.X_EVP_sha256(), nil) {
		fmt.Errorf("Invalid digest init.\n")
		return false
	}

	buf := buffer.Bytes()
	return mrenclave_update(ctx, unsafe.Pointer(&(buf[0])))
}

func mrenclave_eadd(ctx *C.EVP_MD_CTX, offset uint64, flags uint64) bool {
	mmreadd := &mreadd{}

	size := uint(binary.Size(*mmreadd))
	GoMemSet(unsafe.Pointer(mmreadd), 0, size)
	mmreadd.tag = MREADD
	mmreadd.offset = offset
	mmreadd.flags = flags

	return mrenclave_update(ctx, unsafe.Pointer(mmreadd))
}

func mrenclave_eextend(ctx *C.EVP_MD_CTX, offset uint64, data unsafe.Pointer) bool {
	mmreextend := &mreextend{}

	var i uint64
	for i = 0; i < 0x1000; i = i + 0x100 {
		size := uint(binary.Size(*mmreextend))
		GoMemSet(unsafe.Pointer(mmreextend), 0, size)
		mmreextend.tag = MREEXTEND
		mmreextend.offset = offset + i

		if ret := mrenclave_update(ctx, unsafe.Pointer(mmreextend)); !ret {
			fmt.Errorf("mrextend error with data location 0x%x.\n", mmreextend.tag)
			return false
		}

		temp := uint(i + 0x00)
		newdata := MovePointer(data, temp)

		if ret := mrenclave_update(ctx, newdata); !ret {
			fmt.Errorf("mrextend error with data location 0x%x.\n", temp)
			return false
		}

		temp = uint(i + 0x40)
		newdata = MovePointer(data, temp)
		if ret := mrenclave_update(ctx, newdata); !ret {
			fmt.Errorf("mrextend error with data location %x.\n", temp)
			return false
		}

		temp = uint(i + 0x80)
		newdata = MovePointer(data, temp)
		if ret := mrenclave_update(ctx, newdata); !ret {
			fmt.Errorf("mrextend error with data location 0x%x.\n", temp)
			return false
		}

		temp = uint(i + 0xC0)
		newdata = MovePointer(data, temp)
		if ret := mrenclave_update(ctx, newdata); !ret {
			fmt.Errorf("mrextend error with data location 0x%x.\n", temp)
			return false
		}
	}

	return true

}

func Measure_Encl(path string, mrenclave unsafe.Pointer, maxmapsize uint64) bool {
	var flags uint64
	var offset uint64
	var ssa_frame_size uint32
	var xfrm uint64
	var mmapsize uint64
	var isoutoftree bool
	var encloffset uint64
	var enclsize uint64
	var mapminaddr uint64
	sgxtcs := &SgxTCS{}

	C.get_sgx_xfrm_by_cpuid((*C.ulong)(&xfrm))
	miscselect := C.get_sgx_miscselect_by_cpuid()
	C.get_mmap_min_addr((*C.ulong)(&mapminaddr))

	ctx := C.X_EVP_MD_CTX_new()
	if ctx == nil {
		fmt.Errorf("ctx init falied.\n")
		return false
	}

	f, err := os.OpenFile(path, os.O_RDONLY, 0600)
	defer f.Close()
	if err != nil {
		fmt.Errorf("target bin file open failed.\n")
		fmt.Printf("target bin file open failed with err %s.\n", err)
		C.X_EVP_MD_CTX_free(ctx)
		return false
	}

	fileinfo, err := os.Stat(path)
	if err != nil {
		fmt.Errorf("target bin file stat failed.\n")
		fmt.Printf("target bin file stat failed.\n")
		return false
	}

	temp := uint64(fileinfo.Size())
	/*if (temp == 0) || ((temp & 0xfff) != 0) {
		fmt.Errorf("target bin file size incorrect.\n")
		fmt.Printf("target bin file size incorrect.\n")
		return false
	}*/

	ssa_frame_size = (uint32)(C.sgx_calc_ssaframesize((C.uint32_t)(miscselect), (C.uint64_t)(xfrm)))
	mmapsize = temp + ((uint64)(ssa_frame_size))*STD_PAGE_SIZE
	if maxmapsize != 0 {
		if maxmapsize < mmapsize {
			fmt.Printf("invlid enclave mmap size 0x%x, please set encalve size large than 0x%x.\n", maxmapsize, mmapsize)
			return false
		}
		mmapsize = maxmapsize
		fmt.Printf("maxmapsize size is 0x%x.\n", maxmapsize)
	}

	if ret := mmapsize % STD_PAGE_SIZE; ret != 0 {
		mmapsize = (mmapsize/STD_PAGE_SIZE + 1) * STD_PAGE_SIZE
		fmt.Printf("mmap size is 0x%x.\n", mmapsize)
	}

	isoutoftree = (bool)(C.is_oot_kernel_driver())
	encloffset = (uint64)(C.calc_enclave_offset((C.uint64_t)(mapminaddr), (C.bool)(!isoutoftree)))
	enclsize = (uint64)(C.powtwo((C.uint64_t)(encloffset + mmapsize)))

	buffer := make([]byte, temp)
	n, err := f.Read(buffer)
	fmt.Printf("target bin file size read n is 0x%x.\n", n)
	if err != nil && err != io.EOF {
		fmt.Errorf("target bin file size read error %s.\n", err)
	}
	sgxtcs = (*SgxTCS)((unsafe.Pointer)(&buffer[0]))
	sgxtcs.ssa_offset = encloffset + (uint64)(C.alignup((C.uint64_t)(temp), STD_PAGE_SIZE))
	sgxtcs.entry_offset = sgxtcs.entry_offset + encloffset

	if ret := mrenclave_ecreate(ctx, temp, uint32(miscselect), xfrm, unsafe.Pointer(&ssa_frame_size), enclsize); !ret {
		return false
	}

	//var offset uint64
	var binoffset uint64
	binoffset = 0

	for offset = encloffset; offset < encloffset+temp; offset = offset + 0x1000 {
		if offset == encloffset {
			flags = SGX_SECINFO_TCS
		} else {
			flags = SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X
		}

		if ret := mrenclave_eadd(ctx, offset, flags); !ret {
			return false
		}

		if ret := mrenclave_eextend(ctx, offset, unsafe.Pointer(&buffer[0+binoffset])); !ret {
			C.X_EVP_MD_CTX_free(ctx)
			return false
		}
		binoffset = binoffset + STD_PAGE_SIZE
	}

	data := make([]byte, 0x1000)
	GoMemSet(unsafe.Pointer(&data[0]), 0, 0x1000)
	flags = SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X
	for ; offset < encloffset+mmapsize; offset = offset + 0x1000 {
		if ret := mrenclave_eadd(ctx, offset, flags); !ret {
			return false
		}
		if ret := mrenclave_eextend(ctx, offset, unsafe.Pointer(&data[0])); !ret {
			C.X_EVP_MD_CTX_free(ctx)
			return false
		}
	}

	if ret := mrenclave_commit(ctx, mrenclave); !ret {
		C.X_EVP_MD_CTX_free(ctx)
		return false
	}

	C.X_EVP_MD_CTX_free(ctx)
	return true

}

func Mrencalve_Verify(targetmrenclave unsafe.Pointer, newmrenclave unsafe.Pointer) bool {
	targetptr := uintptr(unsafe.Pointer(targetmrenclave))
	newptr := uintptr(unsafe.Pointer(newmrenclave))
	for i := 0; i < MRENCALVE_HASH_SIZE; i++ {
		targetByte := (*byte)(unsafe.Pointer(targetptr + uintptr(i)))
		newByte := (*byte)(unsafe.Pointer(newptr + uintptr(i)))
		if *targetByte != *newByte {
			fmt.Printf("mrencalve compare failed: target meenclave 0x%x ; new mrenclave 0x%x.\n", *targetByte, *newByte)
			return false
		} else {
			fmt.Printf("mrencalve compare success: this is the %d byte with value 0x%x.\n", i, *targetByte)
		}
	}
	return true
}

func Mrencalve_VerifybySigstruct(sigstruct string, newmrenclave unsafe.Pointer) bool {

	f, err := os.OpenFile(sigstruct, os.O_RDONLY, 0600)
	defer f.Close()
	if err != nil {
		fmt.Errorf("sigstruct file open failed.\n")
		return false
	}

	fileinfo, err := os.Stat(sigstruct)
	if err != nil {
		fmt.Errorf("target bin file stat failed.\n")
		return false
	}

	temp := fileinfo.Size()
	if (temp == 0) || (temp != SIGSTRUCT_SIZE) {
		fmt.Errorf("sigstruct file size incorrect.\n")
		return false
	}

	buffer := make([]byte, SIGSTRUCT_SIZE)
	n, err := f.Read(buffer)
	if (err != nil) || (n != SIGSTRUCT_SIZE) {
		fmt.Errorf("sisgstruct file read error %s. the size is %d\n", err, n)
		return false
	}

	sigstructobj := &SigStruct{}
	restruct.Unpack(buffer, binary.LittleEndian, &sigstructobj)
	if err != nil {
		fmt.Errorf("sisgstruct from byte convert to struct read error %s.\n", err)
		return false
	}

	var mrencalve [MRENCALVE_HASH_SIZE]byte
	mrencalve = sigstructobj.EnclaveHash
	ptr := uintptr(unsafe.Pointer(newmrenclave))
	for i := 0; i < MRENCALVE_HASH_SIZE; i++ {
		pByte := (*byte)(unsafe.Pointer(ptr + uintptr(i)))
		if mrencalve[i] != *pByte {
			fmt.Printf("mrencalve compare failed: target meenclave 0x%x ; new mrenclave 0x%x.\n", mrencalve[i], *pByte)
			return false
		} else {
			fmt.Printf("mrencalve compare success: this is the %d byte with value 0x%x.\n", i, mrencalve[i])
		}
	}
	return true
}
