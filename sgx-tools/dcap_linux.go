package main // import "github.com/inclavare-containers/sgx-tools"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/go-restruct/restruct"
	"github.com/golang/protobuf/proto"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	pb "github.com/inclavare-containers/sgx-tools/proto"
	"github.com/sirupsen/logrus"
	"net"
	"strings"
)

const (
	aesmdSocket                  = "/var/run/aesmd/aesm.socket"
	attestationKeyIdentityLength = 256
	nonceLength                  = 16
	qeReportInfoLength           = 960
	// In millisecond
	aesmdTimeOut     = 15000
	rawMessageLength = 4
)

// dialAesmd: a duplicated function inherited from intelsgx package
func dialAesmd() (*net.UnixConn, error) {
	addr, err := net.ResolveUnixAddr("unix", aesmdSocket)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// transmitAesmd: a duplicated function inherited from intelsgx package
func transmitAesmd(conn *net.UnixConn, req *pb.AesmServiceRequest) ([]byte, error) {
	rdata, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}

	msgSize := uint32(len(rdata))
	byteBuf := bytes.NewBuffer([]byte{})
	binary.Write(byteBuf, binary.LittleEndian, &msgSize)
	if _, err = conn.Write(byteBuf.Bytes()); err != nil {
		return nil, err
	}

	if _, err = conn.Write(rdata); err != nil {
		return nil, err
	}

	rdata = append(rdata[:rawMessageLength])
	if _, err = conn.Read(rdata); err != nil {
		return nil, err
	}

	byteBuf = bytes.NewBuffer(rdata)
	if err = binary.Read(byteBuf, binary.LittleEndian, &msgSize); err != nil {
		return nil, err
	}

	rdata = make([]byte, msgSize)
	var msgSizeRead int
	msgSizeRead, err = conn.Read(rdata)
	if err != nil {
		return nil, err
	}

	if msgSizeRead != int(msgSize) {
		return nil, fmt.Errorf("invalid response size (returned %d, expected %d)",
			msgSizeRead, msgSize)
	}

	return rdata, nil
}

func DumpTargetInfo(targetInfo []byte) error {
	ti := &intelsgx.Targetinfo{}
	if err := restruct.Unpack(targetInfo, binary.LittleEndian, &ti); err != nil {
		return err
	}

	logrus.Debugf("Quoting Enclave's TARGETINFO:\n")
	logrus.Debugf("  Enclave Hash:       0x%v\n",
		hex.EncodeToString(ti.Measurement[:]))
	logrus.Debugf("  Enclave Attributes: 0x%v\n",
		hex.EncodeToString(ti.Attributes[:]))
	logrus.Debugf("  CET Attributes:     %#02x\n",
		ti.CetAttributes)
	logrus.Debugf("  Config SVN:         %#04x\n",
		ti.ConfigSvn)
	logrus.Debugf("  Misc Select:        %#08x\n",
		ti.MiscSelect)
	logrus.Debugf("  Config ID:          0x%v\n",
		hex.EncodeToString(ti.ConfigId[:]))

	return nil
}

func DumpLocalReport(report []byte) error {
	r := &intelsgx.Report{}
	if err := restruct.Unpack(report, binary.LittleEndian, &r); err != nil {
		return err
	}

	logrus.Debugf("REPORT:")
	logrus.Debugf("  CPU SVN:                        0x%v\n",
		hex.EncodeToString(r.CpuSvn[:]))
	logrus.Debugf("  Misc Select:                    %#08x\n",
		r.MiscSelect)
	logrus.Debugf("  Product ID:                     0x%v\n",
		hex.EncodeToString(r.IsvExtProdId[:]))
	logrus.Debugf("  Attributes:                     0x%v\n",
		hex.EncodeToString(r.Attributes[:]))
	logrus.Debugf("  Enclave Hash:                   0x%v\n",
		hex.EncodeToString(r.MrEnclave[:]))
	logrus.Debugf("  Enclave Signer:                 0x%v\n",
		hex.EncodeToString(r.MrSigner[:]))
	logrus.Debugf("  Config ID:                      0x%v\n",
		hex.EncodeToString(r.ConfigId[:]))
	logrus.Debugf("  ISV assigned Produdct ID:       %#04x\n",
		r.IsvProdId)
	logrus.Debugf("  ISV assigned SVN:               %d\n",
		r.IsvSvn)
	logrus.Debugf("  Config SVN:                     %#04x\n",
		r.ConfigSvn)
	logrus.Debugf("  ISV assigned Product Family ID: 0x%v\n",
		hex.EncodeToString(r.IsvFamilyId[:]))
	logrus.Debugf("  Report Data:                    0x%v\n",
		hex.EncodeToString(r.ReportData[:]))

	return nil
}

func initQuoteExRequest(akId []byte, akPubKeyRequired bool, bufSize uint64) ([]byte, uint64, error) {
	conn, err := dialAesmd()
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	req := pb.AesmServiceRequest{}
	req.InitQuoteExReq = &pb.AesmServiceRequest_InitQuoteExRequest{
		AttKeyId:         akId,
		BufSize:          bufSize,
		BPubKeyIdPresent: &pb.AesmServiceRequest_InitQuoteExRequest_BPubKeyId{BPubKeyId: akPubKeyRequired},
		Timeout:          aesmdTimeOut,
	}

	rdata, err := transmitAesmd(conn, &req)
	if err != nil {
		return nil, 0, err
	}

	resp := pb.AesmServiceResponse{}
	resp.InitQuoteExRes = &pb.AesmServiceResponse_InitQuoteExResponse{}
	if err := proto.Unmarshal(rdata, &resp); err != nil {
		return nil, 0, err
	}

	if errCode := resp.InitQuoteExRes.GetErrorCode(); errCode != 0 {
		return nil, 0, fmt.Errorf("failed to call initQuoteExRequest (error code = %d)", errCode)
	}

	return resp.InitQuoteExRes.GetTargetInfo(), resp.InitQuoteExRes.GetPubKeyIdSize(), nil
}

func getQuoteSizeExRequest(akId []byte) (uint32, error) {
	conn, err := dialAesmd()
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	req := pb.AesmServiceRequest{}
	req.GetQuoteSizeExReq = &pb.AesmServiceRequest_GetQuoteSizeExRequest{
		AttKeyId: akId,
		Timeout:  aesmdTimeOut,
	}

	rdata, err := transmitAesmd(conn, &req)
	if err != nil {
		return 0, err
	}

	resp := pb.AesmServiceResponse{}
	resp.GetQuoteSizeExRes = &pb.AesmServiceResponse_GetQuoteSizeExResponse{}
	if err := proto.Unmarshal(rdata, &resp); err != nil {
		return 0, err
	}

	if errCode := resp.GetQuoteSizeExRes.GetErrorCode(); errCode != 0 {
		return 0, fmt.Errorf("failed to call getQuoteSizeExRequest (error code = %d)", errCode)
	}

	return resp.GetQuoteSizeExRes.GetQuoteSize(), nil
}

func getQuoteExRequest(akId []byte, report []byte, quoteSize uint32) ([]byte, error) {
	conn, err := dialAesmd()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := pb.AesmServiceRequest{}
	req.GetQuoteExReq = &pb.AesmServiceRequest_GetQuoteExRequest{
		Report:       report,
		AttKeyId:     akId,
		QeReportInfo: nil,
		BufSize:      quoteSize,
		Timeout:      aesmdTimeOut,
	}

	rdata, err := transmitAesmd(conn, &req)
	if err != nil {
		return nil, err
	}

	resp := pb.AesmServiceResponse{}
	resp.GetQuoteExRes = &pb.AesmServiceResponse_GetQuoteExResponse{}
	if err := proto.Unmarshal(rdata, &resp); err != nil {
		return nil, err
	}

	if errCode := resp.GetQuoteExRes.GetErrorCode(); errCode != 0 {
		return nil, fmt.Errorf("failed to call getQuoteExRequest (error code = %d)", errCode)
	}

	return resp.GetQuoteExRes.GetQuote(), nil
}

func selectAttKeyIDRequest() ([]byte, error) {
	conn, err := dialAesmd()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := pb.AesmServiceRequest{}
	req.SelectAttKeyIDReq = &pb.AesmServiceRequest_SelectAttKeyIDRequest{
		// AttKeyIdList is optional for aesmd so that we don't need to fill in the corresponding Attestation Key Identity List
		AttKeyIdList: nil,
		Timeout:      aesmdTimeOut,
	}

	rdata, err := transmitAesmd(conn, &req)
	if err != nil {
		return nil, err
	}

	resp := pb.AesmServiceResponse{}
	resp.SelectAttKeyIDRes = &pb.AesmServiceResponse_SelectAttKeyIDResponse{}
	if err := proto.Unmarshal(rdata, &resp); err != nil {
		return nil, err
	}

	if errCode := resp.SelectAttKeyIDRes.GetErrorCode(); errCode != 0 {
		return nil, fmt.Errorf("failed to call selectAttKeyIDRequest (error code = %d)", errCode)
	}

	return resp.SelectAttKeyIDRes.GetSelectedAttKeyId(), nil
}

func getSupportedAttKeyIDNumRequest() (uint32, error) {
	conn, err := dialAesmd()
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	req := pb.AesmServiceRequest{}
	req.GetSupportedAttKeyIDNumReq = &pb.AesmServiceRequest_GetSupportedAttKeyIDNumRequest{
		Timeout: aesmdTimeOut,
	}

	rdata, err := transmitAesmd(conn, &req)
	if err != nil {
		return 0, err
	}

	resp := pb.AesmServiceResponse{}
	resp.GetSupportedAttKeyIDNumRes = &pb.AesmServiceResponse_GetSupportedAttKeyIDNumResponse{}
	if err := proto.Unmarshal(rdata, &resp); err != nil {
		return 0, err
	}

	if errCode := resp.GetSupportedAttKeyIDNumRes.GetErrorCode(); errCode != 0 {
		return 0, fmt.Errorf("failed to call getSupportedAttKeyIDNumRequest (error code = %d)", errCode)
	}

	return resp.GetSupportedAttKeyIDNumRes.GetAttKeyIdNum(), nil
}

func getSupportedAttKeyIDsRequest(num uint32) ([]byte, error) {
	conn, err := dialAesmd()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := pb.AesmServiceRequest{}
	req.GetSupportedAttKeyIDsReq = &pb.AesmServiceRequest_GetSupportedAttKeyIDsRequest{
		BufSize: num * attestationKeyIdentityLength,
		Timeout: aesmdTimeOut,
	}

	rdata, err := transmitAesmd(conn, &req)
	if err != nil {
		return nil, err
	}

	resp := pb.AesmServiceResponse{}
	resp.GetSupportedAttKeyIDsRes = &pb.AesmServiceResponse_GetSupportedAttKeyIDsResponse{}
	if err := proto.Unmarshal(rdata, &resp); err != nil {
		return nil, err
	}

	if errCode := resp.GetSupportedAttKeyIDsRes.GetErrorCode(); errCode != 0 {
		return nil, fmt.Errorf("failed to call getSupportedAttKeyIDsRequest (error code = %d)", errCode)
	}

	return resp.GetSupportedAttKeyIDsRes.GetAttKeyIds(), nil
}

func getAttestationKeyIdentity(quoteType string) ([]byte, error) {
	akId, err := selectAttKeyIDRequest()
	if err != nil {
		return nil, err
	}
	if akId == nil {
		return nil, fmt.Errorf("failed to call selectAttKeyIDRequest")
	}

	akIdentity := &attestationKeyIdentity{}
	if err = restruct.Unpack(akId, binary.LittleEndian, &akIdentity); err != nil {
		return nil, err
	}

	if strings.EqualFold(quoteType, quoteTypeEcdsa) && (akIdentity.AlgorithmId == sgxQuoteLibraryAlgorithmEcdsaP256 || akIdentity.AlgorithmId == sgxQuoteLibraryAlgorithmEcdsaP384) {
		return akId, nil
	} else if (strings.EqualFold(quoteType, quoteTypeEpidUnlinkable) || strings.EqualFold(quoteType, quoteTypeEpidLinkable)) && akIdentity.AlgorithmId == sgxQuoteLibraryAlgorithmEpid {
		return akId, nil
	}

	akIdNum, err := getSupportedAttKeyIDNumRequest()
	if err != nil {
		return nil, err
	}
	if akIdNum == 0 {
		return nil, fmt.Errorf("failed to call getSupportedAttKeyIDNumRequest: invalid Attestation Key Identity Number = %d", akIdNum)
	}

	akIdList, err := getSupportedAttKeyIDsRequest(akIdNum)
	if err != nil {
		return nil, err
	}
	if akIdList == nil {
		return nil, fmt.Errorf("failed to call getSupportedAttKeyIDsRequest")
	}

	var i uint32 = 0
	for i < akIdNum {
		akId := akIdList[i*attestationKeyIdentityLength : (i+1)*attestationKeyIdentityLength]

		akIdentity := &attestationKeyIdentity{}
		if err = restruct.Unpack(akId, binary.LittleEndian, &akIdentity); err != nil {
			return nil, err
		}

		if strings.EqualFold(quoteType, quoteTypeEcdsa) && (akIdentity.AlgorithmId == sgxQuoteLibraryAlgorithmEcdsaP256 || akIdentity.AlgorithmId == sgxQuoteLibraryAlgorithmEcdsaP384) {
			return akId, nil
		} else if (strings.EqualFold(quoteType, quoteTypeEpidUnlinkable) || strings.EqualFold(quoteType, quoteTypeEpidLinkable)) && akIdentity.AlgorithmId == sgxQuoteLibraryAlgorithmEpid {
			return akId, nil
		}

		i++
	}

	return nil, nil
}

func GetQeTargetInfoEx(quoteType string) ([]byte, error) {
	var ti []byte

	akId, err := getAttestationKeyIdentity(quoteType)
	if err != nil {
		return nil, err
	}
	if len(akId) != attestationKeyIdentityLength {
		return nil, fmt.Errorf("len(attKeyId) is not %d but %d", attestationKeyIdentityLength, len(akId))
	}

	if strings.EqualFold(quoteType, quoteTypeEcdsa) {
		_, bufSize, err := initQuoteExRequest(akId, false, uint64(0))
		if err != nil {
			return nil, err
		}
		if bufSize == 0 {
			return nil, fmt.Errorf("failed to call initQuoteExRequest: invalid Public Key Identity Size: %d\n", bufSize)
		}

		ti, _, err = initQuoteExRequest(akId, true, bufSize)
		if err != nil {
			return nil, err
		}
		if len(ti) != intelsgx.TargetinfoLength {
			return nil, fmt.Errorf("failed to call initQuoteExRequest: invalid length of targetinfo (returned %d, expected %d)", len(ti), intelsgx.TargetinfoLength)
		}
		if err = DumpTargetInfo(ti); err != nil {
			return nil, fmt.Errorf("Invalid target info")
		}
	} else if strings.EqualFold(quoteType, quoteTypeEpidUnlinkable) || strings.EqualFold(quoteType, quoteTypeEpidLinkable) {
		ti, err = intelsgx.GetQeTargetInfo()
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("failed to call GetQeTargetInfoEx: unsupported SGX quote type!")
	}

	return ti, nil
}

func GetQuoteEx(quoteType string, report []byte, spid string) ([]byte, error) {
	var quote []byte

	err := DumpLocalReport(report)
	if err != nil {
		return nil, err
	}

	akId, err := getAttestationKeyIdentity(quoteType)
	if err != nil {
		return nil, err
	}
	if len(akId) != attestationKeyIdentityLength {
		return nil, fmt.Errorf("len(attKeyId) is not %d but %d", attestationKeyIdentityLength, len(akId))
	}

	if strings.EqualFold(quoteType, quoteTypeEcdsa) {
		quoteSize, err := getQuoteSizeExRequest(akId)
		if err != nil {
			return nil, err
		}
		if quoteSize == 0 {
			return nil, fmt.Errorf("failed to call getQuoteSizeExRequest: invalid Quote Size %d", quoteSize)
		}

		quote, err = getQuoteExRequest(akId, report, quoteSize)
		if err != nil {
			return nil, err
		}
		if quote == nil {
			return nil, fmt.Errorf("failed to call getQuoteExRequest")
		}
		if len(quote) != (int)(quoteSize) {
			return nil, fmt.Errorf("failed to call getQuoteExRequest: len(quote) is not %d but %d\n",
				quoteSize, len(quote))
		}
	} else if strings.EqualFold(quoteType, quoteTypeEpidUnlinkable) || strings.EqualFold(quoteType, quoteTypeEpidLinkable) {
		if spid == "" {
			return nil, fmt.Errorf("failed to call GetQuoteEx: spid argument cannot be empty")
		}

		linkable := false
		if strings.EqualFold(quoteType, quoteTypeEpidLinkable) {
			linkable = true
		}

		quote, err = intelsgx.GetQuote(report, spid, linkable)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("failed to call GetQuoteEx: unsupported SGX quote type!")
	}

	return quote, nil
}
