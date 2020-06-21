package intelsgx // import "github.com/opencontainers/runc/libenclave/intelsgx"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/go-restruct/restruct"
	"github.com/golang/protobuf/proto"
	pb "github.com/opencontainers/runc/libenclave/intelsgx/proto"
	"github.com/sirupsen/logrus"
	"net"
)

const (
	aesmdSocket = "/var/run/aesmd/aesm.socket"
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

	rdata = append(rdata[:4])
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
		Timeout:     10000,
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
		Timeout: 10000,
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

	ti := &Targetinfo{}
	if err := restruct.Unpack(targetInfo, binary.LittleEndian, &ti); err != nil {
		return nil, err
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

	return resp.GetQeTargetInfo.GetTargetinfo(), nil
}
