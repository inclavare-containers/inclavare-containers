package intelsgx // import "github.com/inclavare-containers/rune/libenclave/intelsgx"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/go-restruct/restruct"
	"github.com/golang/protobuf/proto"
	pb "github.com/inclavare-containers/rune/libenclave/intelsgx/proto"
	"github.com/sirupsen/logrus"
	"net"
	"strings"
)

const (
	aesmdSocket = "/var/run/aesmd/aesm.socket"
	nonceLength = 16
	// In millisecond
	aesmdTimeOut     = 15000
	rawMessageLength = 4
)

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
	ti := &Targetinfo{}
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

/* The report can be used as a separate structure or as a member of the quote structure,
 * so we add the indent paramter to both support to dump these two cases.
 */
func DumpLocalReport(report []byte, indent int) error {
	r := &Report{}
	if err := restruct.Unpack(report, binary.LittleEndian, &r); err != nil {
		return err
	}

	if indent < 0 {
		return fmt.Errorf("indent:%d is less than 0", indent)
	}
	indentStr := strings.Repeat(" ", indent)

	logrus.Debugf("%sREPORT:", indentStr)
	logrus.Debugf("%s  CPU SVN:                        0x%v\n",
		indentStr, hex.EncodeToString(r.CpuSvn[:]))
	logrus.Debugf("%s  Misc Select:                    %#08x\n",
		indentStr, r.MiscSelect)
	logrus.Debugf("%s  Product ID:                     0x%v\n",
		indentStr, hex.EncodeToString(r.IsvExtProdId[:]))
	logrus.Debugf("%s  Attributes:                     0x%v\n",
		indentStr, hex.EncodeToString(r.Attributes[:]))
	logrus.Debugf("%s  Enclave Hash:                   0x%v\n",
		indentStr, hex.EncodeToString(r.MrEnclave[:]))
	logrus.Debugf("%s  Enclave Signer:                 0x%v\n",
		indentStr, hex.EncodeToString(r.MrSigner[:]))
	logrus.Debugf("%s  Config ID:                      0x%v\n",
		indentStr, hex.EncodeToString(r.ConfigId[:]))
	logrus.Debugf("%s  ISV assigned Produdct ID:       %#04x\n",
		indentStr, r.IsvProdId)
	logrus.Debugf("%s  ISV assigned SVN:               %d\n",
		indentStr, r.IsvSvn)
	logrus.Debugf("%s  Config SVN:                     %#04x\n",
		indentStr, r.ConfigSvn)
	logrus.Debugf("%s  ISV assigned Product Family ID: 0x%v\n",
		indentStr, hex.EncodeToString(r.IsvFamilyId[:]))
	logrus.Debugf("%s  Report Data:                    0x%v\n",
		indentStr, hex.EncodeToString(r.ReportData[:]))

	return nil
}

func DumpQuote(quote []byte) error {
	q := &Quote{}
	if err := restruct.Unpack(quote, binary.LittleEndian, &q); err != nil {
		return err
	}

	logrus.Debugf("QUOTE:")
	logrus.Debugf("  Version:					%d\n",
		q.Version)
	logrus.Debugf("  Signature Type:				%d\n",
		q.SignatureType)

	if q.Version == QuoteVersion2 {
		quoteBody := &QuoteBodyV2{}
		if err := restruct.Unpack(quote[QuoteHeaderLength:QuoteHeaderLength+QuoteBodyLength], binary.LittleEndian, &quoteBody); err != nil {
			return err
		}

		logrus.Debugf("  Gid:					%#08x\n",
			quoteBody.Gid)
		logrus.Debugf("  ISV assigned SVN for Quoting Enclave:	%d\n",
			quoteBody.ISVSvnQe)
		logrus.Debugf("  ISV assigned SVN for PCE:		%d\n",
			quoteBody.ISVSvnPce)
		logrus.Debugf("  Base name:				0x%v\n",
			hex.EncodeToString(quoteBody.Basename[:]))
	} else if q.Version == QuoteVersion3 {
		quoteBody := &QuoteBodyV3{}
		if err := restruct.Unpack(quote[QuoteHeaderLength:QuoteHeaderLength+QuoteBodyLength], binary.LittleEndian, &quoteBody); err != nil {
			return err
		}

		logrus.Debugf("  Quoting Enclave SVN:			%d\n",
			quoteBody.QeSvn)
		logrus.Debugf("  PCE SVN:				%d\n",
			quoteBody.PceSvn)
		logrus.Debugf("  Quoting Enclave Vendor Id:		0x%v\n",
			hex.EncodeToString(quoteBody.QeVendorId[:]))
		logrus.Debugf("  User Data:				0x%v\n",
			hex.EncodeToString(quoteBody.UserData[:]))
	} else {
		return fmt.Errorf("Unsupported Quote Version: %d", q.Version)
	}

	err := DumpLocalReport(quote[QuoteHeaderLength+QuoteBodyLength:QuoteHeaderLength+QuoteBodyLength+ReportLength], 2)
	if err != nil {
		return nil
	}

	logrus.Debugf("  Signature Length:				%d\n",
		q.SigLen)

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

	return resp.InitQuoteExRes.GetTargetInfo(), resp.InitQuoteExRes.GetPubKeyIdSize(), err
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

	return resp.GetQuoteSizeExRes.GetQuoteSize(), err
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

	return resp.GetQuoteExRes.GetQuote(), err
}

func selectAttKeyIDRequest() ([]byte, error) {
	conn, err := dialAesmd()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := pb.AesmServiceRequest{}
	req.SelectAttKeyIDReq = &pb.AesmServiceRequest_SelectAttKeyIDRequest{
		/* aesmd will automatically find and traverse the attestation key identity list to
		 * return the appropriate attestation key identity so that we don't need to
		 * fill in the list any more.
		 */
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

	return resp.SelectAttKeyIDRes.GetSelectedAttKeyId(), err
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

	return resp.GetSupportedAttKeyIDNumRes.GetAttKeyIdNum(), err
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

	return resp.GetSupportedAttKeyIDsRes.GetAttKeyIds(), err
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

	if strings.EqualFold(quoteType, QuoteTypeEcdsa) && (akIdentity.AlgorithmId == sgxQuoteLibraryAlgorithmEcdsaP256 || akIdentity.AlgorithmId == sgxQuoteLibraryAlgorithmEcdsaP384) {
		return akId, err
	}

	if (strings.EqualFold(quoteType, QuoteTypeEpidUnlinkable) || strings.EqualFold(quoteType, QuoteTypeEpidLinkable)) && akIdentity.AlgorithmId == sgxQuoteLibraryAlgorithmEpid {
		return akId, err
	}

	/* If the attestation key identity returned by aesmd does not match the quote type specified by the user,
	 * then traversing the attestation key identity list of aesmd to find the attestation key identity
	 * that matches the user's quote type.
	 */
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

		if strings.EqualFold(quoteType, QuoteTypeEcdsa) && (akIdentity.AlgorithmId == sgxQuoteLibraryAlgorithmEcdsaP256 || akIdentity.AlgorithmId == sgxQuoteLibraryAlgorithmEcdsaP384) {
			return akId, err
		}

		if (strings.EqualFold(quoteType, QuoteTypeEpidUnlinkable) || strings.EqualFold(quoteType, QuoteTypeEpidLinkable)) && akIdentity.AlgorithmId == sgxQuoteLibraryAlgorithmEpid {
			return akId, err
		}

		i++
	}

	return nil, err
}

func GetLaunchToken(sig []byte) ([]byte, error) {
	if len(sig) != SigStructLength {
		return nil, fmt.Errorf("signature not match SIGSTRUCT")
	}

	s := &SigStruct{}
	if err := restruct.Unpack(sig, binary.LittleEndian, &s); err != nil {
		return nil, err
	}

	mrenclave := s.EnclaveHash[:]
	modulus := s.Modulus[:]
	attributes := s.Attributes[:]

	logrus.Debugf("SIGSTRUCT:")
	_ = s.Header[:]
	logrus.Debugf("  Enclave Vendor:                   %#08x\n",
		s.Vendor)
	logrus.Debugf("  Enclave Build Date:               %d-%d-%d\n",
		s.BuildYear, s.BuildMonth, s.BuildDay)
	logrus.Debugf("  Software Defined:                 %#08x\n",
		s.SwDefined)
	logrus.Debugf("  ISV assigned Product Family ID:   0x%v\n",
		hex.EncodeToString(s.ISVFamilyId[:]))
	logrus.Debugf("  ISV assigned Produdct ID:         %#04x\n",
		s.ISVProdId)
	logrus.Debugf("  ISV assigned Extended Product ID: 0x%v\n",
		hex.EncodeToString(s.ISVExtProdId[:]))
	logrus.Debugf("  ISV assigned SVN:                 %d\n", s.ISVSvn)
	logrus.Debugf("  Enclave Attributes:               0x%v\n",
		hex.EncodeToString(attributes))
	logrus.Debugf("  Enclave Attributes Mask:          0x%v\n",
		hex.EncodeToString(s.AttributesMask[:]))
	logrus.Debugf("  Enclave Misc Select:              %#08x\n",
		s.MiscSelect)
	logrus.Debugf("  Enclave Misc Mask:                %#08x\n",
		s.MiscMask)
	logrus.Debugf("  Enclave Hash:                     0x%v\n",
		hex.EncodeToString(mrenclave))
	logrus.Debugf("  Modulus:                          0x%v...\n",
		hex.EncodeToString(modulus[:32]))
	logrus.Debugf("  Exponent:                         %d\n",
		s.Exponent)
	logrus.Debugf("  Signature:                        0x%v...\n",
		hex.EncodeToString(s.Signature[:32]))
	logrus.Debugf("  Q1:                               0x%v...\n",
		hex.EncodeToString(s.Q1[:32]))
	logrus.Debugf("  Q2:                               0x%v...\n",
		hex.EncodeToString(s.Q2[:32]))

	conn, err := dialAesmd()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := pb.AesmServiceRequest{}
	req.GetLaunchToken = &pb.AesmServiceRequest_GetLaunchToken{
		Enclavehash: mrenclave,
		Modulus:     modulus,
		Attributes:  attributes,
		Timeout:     aesmdTimeOut,
	}

	rdata, err := transmitAesmd(conn, &req)
	if err != nil {
		return nil, err
	}

	resp := pb.AesmServiceResponse{}
	resp.GetLaunchToken = &pb.AesmServiceResponse_GetLaunchToken{}
	if err := proto.Unmarshal(rdata, &resp); err != nil {
		return nil, err
	}

	if resp.GetLaunchToken.GetError() != 0 {
		return nil, fmt.Errorf("failed to get EINITTOKEN (error code = %d)",
			resp.GetLaunchToken.GetError())
	}

	token := resp.GetLaunchToken.GetToken()
	if len(token) != EinittokenLength {
		return nil, fmt.Errorf("invalid length of token: (returned %d, expected %d)",
			len(token), EinittokenLength)
	}

	tok := &Einittoken{}
	if err := restruct.Unpack(token, binary.LittleEndian, &tok); err != nil {
		return nil, err
	}

	logrus.Debugf("EINITTOKEN:\n")
	logrus.Debugf("  Valid:                                    %d\n",
		tok.Valid)
	logrus.Debugf("  Enclave Attributes:                       0x%v\n",
		hex.EncodeToString(tok.Attributes[:]))
	logrus.Debugf("  Enclave Hash:                             0x%v\n",
		hex.EncodeToString(tok.MrEnclave[:]))
	logrus.Debugf("  Enclave Signer:                           0x%v\n",
		hex.EncodeToString(tok.MrSigner[:]))
	logrus.Debugf("  Launch Enclave's CPU SVN :                0x%v\n",
		hex.EncodeToString(tok.CpuSvnLe[:]))
	logrus.Debugf("  Launch Enclave's ISV assigned Product ID: %#04x\n",
		tok.ISVProdIdLe)
	logrus.Debugf("  Launch Enclave's ISV assigned SVN:        %d\n",
		tok.ISVSvnLe)
	logrus.Debugf("  Launch Enclave's Masked Misc Select:      %#08x\n",
		tok.MaskedMiscSelectLe)
	logrus.Debugf("  Launch Enclave's Masked Attributes:       0x%v\n",
		hex.EncodeToString(tok.MaskedAttributesLe[:]))
	logrus.Debugf("  Key ID:                                   0x%v\n",
		hex.EncodeToString(tok.KeyId[:]))
	logrus.Debugf("  MAC:                                      0x%v\n",
		hex.EncodeToString(tok.Mac[:]))

	return resp.GetLaunchToken.GetToken(), nil
}

func GetQeTargetInfo() ([]byte, error) {
	conn, err := dialAesmd()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := pb.AesmServiceRequest{}
	req.GetQeTargetInfo = &pb.AesmServiceRequest_GetQeTargetInfo{
		Timeout: aesmdTimeOut,
	}

	rdata, err := transmitAesmd(conn, &req)
	if err != nil {
		return nil, err
	}

	resp := pb.AesmServiceResponse{}
	resp.GetQeTargetInfo = &pb.AesmServiceResponse_GetQeTargetInfo{}
	if err := proto.Unmarshal(rdata, &resp); err != nil {
		return nil, err
	}

	if resp.GetQeTargetInfo.GetError() != 0 {
		return nil, fmt.Errorf("failed to get TARGETINFO (error code = %d)",
			resp.GetQeTargetInfo.GetError())
	}

	targetInfo := resp.GetQeTargetInfo.GetTargetinfo()
	if len(targetInfo) != TargetinfoLength {
		return nil, fmt.Errorf("invalid length of TARGETINFO: (returned %d, expected %d)",
			len(targetInfo), TargetinfoLength)
	}

	if err := DumpTargetInfo(targetInfo); err != nil {
		return nil, err
	}

	return resp.GetQeTargetInfo.GetTargetinfo(), nil
}

func GetQuote(report []byte, spid string, linkable bool) ([]byte, error) {
	if len(report) != ReportLength {
		return nil, fmt.Errorf("signature not match REPORT")
	}

	s, err := hex.DecodeString(spid)
	if err != nil {
		return nil, err
	}
	if len(s) != SpidLength {
		return nil, fmt.Errorf("SPID is not 16-byte long")
	}

	if err := DumpLocalReport(report, 0); err != nil {
		return nil, err
	}

	conn, err := dialAesmd()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var t uint32 = QuoteSignatureTypeUnlinkable
	if linkable == true {
		t = QuoteSignatureTypeLinkable
	}

	req := pb.AesmServiceRequest{}
	req.GetQuote = &pb.AesmServiceRequest_GetQuote{
		Report:           report,
		QuoteTypePresent: &pb.AesmServiceRequest_GetQuote_QuoteType{QuoteType: t},
		Spid:             s,
		BufSize:          SgxEpidMaxQuoteLength,
		QeReportPresent:  &pb.AesmServiceRequest_GetQuote_QeReport{QeReport: false},
		Timeout:          aesmdTimeOut,
	}

	rdata, err := transmitAesmd(conn, &req)
	if err != nil {
		return nil, err
	}

	resp := pb.AesmServiceResponse{}
	resp.GetQuote = &pb.AesmServiceResponse_GetQuote{}
	if err := proto.Unmarshal(rdata, &resp); err != nil {
		return nil, err
	}

	if resp.GetQuote.GetError() != 0 {
		return nil, fmt.Errorf("failed to get QUOTE (error code = %d)",
			resp.GetQuote.GetError())
	}

	quote := resp.GetQuote.GetQuote()
	if len(quote) != SgxEpidMaxQuoteLength {
		return nil, fmt.Errorf("invalid length of epid quote: (returned %d, expected %d)",
			len(quote), SgxEpidMaxQuoteLength)
	}

	err = DumpQuote(quote)
	if err != nil {
		return nil, err
	}

	q := &Quote{}
	if err := restruct.Unpack(quote, binary.LittleEndian, &q); err != nil {
		return nil, err
	}

	return quote[0 : q.SigLen+QuoteLength], nil
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

	if strings.EqualFold(quoteType, QuoteTypeEcdsa) {
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
		if len(ti) != TargetinfoLength {
			return nil, fmt.Errorf("failed to call initQuoteExRequest: invalid length of targetinfo (returned %d, expected %d)", len(ti), TargetinfoLength)
		}
		if err = DumpTargetInfo(ti); err != nil {
			return nil, fmt.Errorf("Invalid target info")
		}
	} else if strings.EqualFold(quoteType, QuoteTypeEpidUnlinkable) || strings.EqualFold(quoteType, QuoteTypeEpidLinkable) {
		ti, err = GetQeTargetInfo()
	} else {
		return nil, fmt.Errorf("failed to call GetQeTargetInfoEx: unsupported SGX quote type!")
	}

	return ti, err
}

func GetQuoteEx(quoteType string, report []byte, spid string) ([]byte, error) {
	var quote []byte

	err := DumpLocalReport(report, 0)
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

	if strings.EqualFold(quoteType, QuoteTypeEcdsa) {
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
	} else if strings.EqualFold(quoteType, QuoteTypeEpidUnlinkable) || strings.EqualFold(quoteType, QuoteTypeEpidLinkable) {
		if spid == "" {
			return nil, fmt.Errorf("failed to call GetQuoteEx: spid argument cannot be empty")
		}

		linkable := false
		if strings.EqualFold(quoteType, QuoteTypeEpidLinkable) {
			linkable = true
		}

		quote, err = GetQuote(report, spid, linkable)
	} else {
		return nil, fmt.Errorf("failed to call GetQuoteEx: unsupported SGX quote type!")
	}

	return quote, err
}
