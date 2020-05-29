package main // import "github.com/inclavare-containers/runectl"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/go-restruct/restruct"
	"github.com/golang/protobuf/proto"
	pb "github.com/inclavare-containers/runectl/proto"
	"github.com/opencontainers/runc/libenclave/intelsgx"
	"github.com/urfave/cli"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	aesmd_socket = "/var/run/aesmd/aesm.socket"
)

var generateTokenCommand = cli.Command{
	Name:  "gen-token",
	Usage: "retrieve a token from aesmd",
	ArgsUsage: `[command options]

EXAMPLE:
For example, generate the token file according to the given signature file:

	# runectl gen-token --signature foo.sig`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "signature",
			Usage: "path to the input signature file (.sig) containing SIGSTRUCT",
		},
		cli.StringFlag{
			Name:  "token",
			Usage: "path to the output token file (.token) containing EINITTOKEN",
		},
	},
	Action: func(context *cli.Context) error {
		sigPath := context.String("signature")
		if sigPath == "" {
			return fmt.Errorf("signature argument cannot be empty")
		}

		sf, err := os.Open(sigPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("signature file %s not found", sigPath)
			}
			return err
		}
		defer sf.Close()

		var sfi os.FileInfo
		sfi, err = sf.Stat()
		if err != nil {
			return err
		}

		if sfi.Size() != intelsgx.SigStructLength {
			return fmt.Errorf("signature file %s not match SIGSTRUCT", sigPath)
		}

		buf := make([]byte, intelsgx.SigStructLength)
		if _, err = io.ReadFull(sf, buf); err != nil {
			return fmt.Errorf("signature file %s read failed", sigPath)
		}

		sig := &intelsgx.SigStruct{}
		if err := restruct.Unpack(buf, binary.LittleEndian, &sig); err != nil {
			log.Println(err)
			return err
		}

		mrenclave := sig.EnclaveHash[:]
		modulus := sig.Modulus[:]
		attributes := sig.Attributes[:]

		if context.GlobalBool("verbose") {
			fmt.Println("SIGSTRUCT:")
			_ = sig.Header[:]
			fmt.Printf("  Enclave Vendor:             %#08x\n",
				sig.Vendor)
			fmt.Printf("  Enclave Build Date:               %d-%d-%d\n",
				sig.BuildYear, sig.BuildMonth, sig.BuildDay)
			fmt.Printf("  Software Defined:           %#08x\n",
				sig.SwDefined)
			fmt.Printf("  ISV assigned Product Family ID:   0x%v\n",
				hex.EncodeToString(sig.ISVFamilyId[:]))
			fmt.Printf("  ISV assigned Produdct ID:         %#04x\n",
				sig.ISVProdId)
			fmt.Printf("  ISV assigned Extended Product ID: 0x%v\n",
				hex.EncodeToString(sig.ISVExtProdId[:]))
			fmt.Printf("  ISV assigned SVN:                 %d\n", sig.ISVSvn)
			fmt.Printf("  Enclave Attributes:               0x%v\n",
				hex.EncodeToString(attributes))
			fmt.Printf("  Enclave Attributes Mask:          0x%v\n",
				hex.EncodeToString(sig.AttributesMask[:]))
			fmt.Printf("  Enclave Misc Select:              %#08x\n",
				sig.MiscSelect)
			fmt.Printf("  Enclave Misc Mask:                %#08x\n",
				sig.MiscMask)
			fmt.Printf("  Enclave Hash:                     0x%v\n",
				hex.EncodeToString(mrenclave))
			fmt.Printf("  Modulus:                          0x%v...\n",
				hex.EncodeToString(modulus[:32]))
			fmt.Printf("  Exponent:                         %d\n",
				sig.Exponent)
			fmt.Printf("  Signature:                        0x%v...\n",
				hex.EncodeToString(sig.Signature[:32]))
			fmt.Printf("  Q1:                               0x%v...\n",
				hex.EncodeToString(sig.Q1[:32]))
			fmt.Printf("  Q2:                               0x%v...\n",
				hex.EncodeToString(sig.Q2[:32]))
		}

		var raddr *net.UnixAddr
		raddr, err = net.ResolveUnixAddr("unix", aesmd_socket)
		if err != nil {
			return err
		}

		var conn *net.UnixConn
		conn, err = net.DialUnix("unix", nil, raddr)
		if err != nil {
			return err
		}

		defer conn.Close()

		req := pb.GetTokenRequestMessage{}
		req.Req = &pb.GetTokenRequest{
			Enclavehash: mrenclave,
			Modulus:     modulus,
			Attributes:  attributes,
			Timeout:     10000,
		}

		var rdata []byte
		rdata, err = proto.Marshal(&req)
		if err != nil {
			return err
		}

		msgSize := uint32(len(rdata))
		byteBuf := bytes.NewBuffer([]byte{})
		binary.Write(byteBuf, binary.LittleEndian, &msgSize)
		if _, err = conn.Write(byteBuf.Bytes()); err != nil {
			return err
		}

		if _, err = conn.Write(rdata); err != nil {
			return err
		}

		rdata = append(rdata[:4])
		if _, err = conn.Read(rdata); err != nil {
			return err
		}

		byteBuf = bytes.NewBuffer(rdata)
		if err = binary.Read(byteBuf, binary.LittleEndian, &msgSize); err != nil {
			return err
		}

		rdata = make([]byte, msgSize)
		var msgSizeRead int
		msgSizeRead, err = conn.Read(rdata)
		if err != nil {
			return err
		}

		if msgSizeRead != int(msgSize) {
			return fmt.Errorf("invalid response size (returned %d, expected %d)",
				msgSizeRead, msgSize)
		}

		resp := pb.GetTokenResponseMessage{}
		resp.Resp = &pb.GetTokenResponse{}
		if err := proto.Unmarshal(rdata, &resp); err != nil {
			return err
		}

		if resp.Resp.GetError() != 0 {
			return fmt.Errorf("failed to get EINITTOKEN (error code = %d)",
				resp.Resp.GetError())
		}

		token := resp.Resp.GetToken()
		if len(token) != intelsgx.EinittokenLength {
			return fmt.Errorf("invalid length of token: (returned %d, expected %d)",
				len(resp.Resp.GetToken()), intelsgx.EinittokenLength)
		}

		tok := &intelsgx.Einittoken{}
		if err := restruct.Unpack(token, binary.LittleEndian, &tok); err != nil {
			log.Println(err)
			return err
		}

		if context.GlobalBool("verbose") {
			fmt.Printf("EINITTOKEN:\n")
			fmt.Printf("  Valid:                                    %d\n",
				tok.Valid)
			fmt.Printf("  Enclave Attributes:                       0x%v\n",
				hex.EncodeToString(tok.Attributes[:]))
			fmt.Printf("  Enclave Hash:                             0x%v\n",
				hex.EncodeToString(tok.MrEnclave[:]))
			fmt.Printf("  Enclave Signer:                           0x%v\n",
				hex.EncodeToString(tok.MrSigner[:]))
			fmt.Printf("  Launch Enclave's CPU SVN :                0x%v\n",
				hex.EncodeToString(tok.CpuSvnLe[:]))
			fmt.Printf("  Launch Enclave's ISV assigned Product ID: %#04x\n",
				tok.ISVProdIdLe)
			fmt.Printf("  Launch Enclave's ISV assigned SVN:        %d\n",
				tok.ISVSvnLe)
			fmt.Printf("  Launch Enclave's Masked Misc Select:      %#08x\n",
				tok.MaskedMiscSelectLe)
			fmt.Printf("  Launch Enclave's Masked Attributes:       0x%v\n",
				hex.EncodeToString(tok.MaskedAttributesLe[:]))
			fmt.Printf("  Key ID:                                   0x%v\n",
				hex.EncodeToString(tok.KeyId[:]))
			fmt.Printf("  MAC:                                      0x%v\n",
				hex.EncodeToString(tok.Mac[:]))
		}

		tokenPath := context.String("token")
		if tokenPath == "" {
			tokenPath = filepath.Dir(sigPath)
			if tokenPath == "." {
				tokenPath = ""
			} else if strings.HasPrefix(tokenPath, "../") {
				if tokenPath, err = filepath.Abs(tokenPath); err != nil {
					return err
				}
				tokenPath += "/"
			} else {
				tokenPath += "/"
			}

			baseName := filepath.Base(sigPath)
			if strings.HasSuffix(baseName, ".sig") {
				tokenPath += baseName[:strings.LastIndex(baseName, ".sig")]
			}
			tokenPath += ".token"
		}

		if err := ioutil.WriteFile(tokenPath, resp.Resp.GetToken(), sfi.Mode().Perm()); err != nil {
			return err
		}

		if context.GlobalBool("verbose") {
			fmt.Printf("token file %s saved\n", tokenPath)
		}

		return nil
	},
	SkipArgReorder: true,
}
