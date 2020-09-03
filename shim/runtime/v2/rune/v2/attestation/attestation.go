package attestation

import (
	"context"
	"fmt"
	"github.com/alibaba/inclavare-containers/shim/runtime/config"
	"github.com/alibaba/inclavare-containers/shim/runtime/v2/rune/constants"
	"github.com/opencontainers/runc/libenclave/attestation/sgx"
	pb "github.com/opencontainers/runc/libenclave/proto"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"net"
	"path"
	"path/filepath"
	"strings"
)

const (
	agentSocket = "agent.sock"
)

const (
	QuoteSignatureTypeUnlinkable = iota
	QuoteSignatureTypeLinkable
	InvalidQuoteSignatureType
)

func dialAgentSocket(root string, containerId string) (*net.UnixConn, error) {
	agentSock := filepath.Join(root, containerId, agentSocket)
	addr, err := net.ResolveUnixAddr("unix", agentSock)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func GetRaParameters(bundlePath string) (raParameters map[string]string, err error) {
	configPath := path.Join(bundlePath, "config.json")
	p := make(map[string]string)

	var spec *specs.Spec
	spec, err = config.LoadSpec(configPath)
	if err != nil {
		return nil, fmt.Errorf("Load Spec:%s error:%s", configPath, err)
	}

	v, ok := config.GetEnv(spec, constants.EnvKeyRaType)
	if !ok {
		logrus.Infof("remote attestation parameters aren't set")
		return nil, nil
	}
	p[constants.EnvKeyRaType] = v

	v, ok = config.GetEnv(spec, constants.EnvKeyIsProductEnclave)
	if !ok {
		return nil, fmt.Errorf("Env:%s isn't set", constants.EnvKeyIsProductEnclave)
	}
	p[constants.EnvKeyIsProductEnclave] = v

	v, ok = config.GetEnv(spec, constants.EnvKeyRaEpidSpid)
	if !ok {
		return nil, fmt.Errorf("Env:%s isn't set", constants.EnvKeyRaEpidSpid)
	}
	p[constants.EnvKeyRaEpidSpid] = v

	v, ok = config.GetEnv(spec, constants.EnvKeyRaEpidSubKey)
	if !ok {
		return nil, fmt.Errorf("Env:%s isn't set", constants.EnvKeyRaEpidSubKey)
	}
	p[constants.EnvKeyRaEpidSubKey] = v

	v, ok = config.GetEnv(spec, constants.EnvKeyRaEpidIsLinkable)
	if !ok {
		return nil, fmt.Errorf("Env:%s isn't set", constants.EnvKeyRaEpidIsLinkable)
	}
	p[constants.EnvKeyRaEpidIsLinkable] = v

	return p, nil
}

func Attest(ctx context.Context, raParameters map[string]string, containerId string, root string) (map[string]string, error) {
	if raParameters == nil {
		return nil, nil
	}

	if raParameters[constants.EnvKeyRaType] == "" {
		return nil, nil
	}

	if !strings.EqualFold(raParameters[constants.EnvKeyRaType], "true") {
		return nil, fmt.Errorf("Unsupported ra type:%s!\n", raParameters[constants.EnvKeyRaType])
	}

	/* spid and subscriptionKey is checked in
	 * package github.com/opencontainers/runc/libenclave/attestation/sgx/ias.
	 * so we only need to check containerId, product and linkable here.
	 */
	if containerId == "" {
		return nil, fmt.Errorf("Invalid container ID!\n")
	}

	if root == "" {
		return nil, fmt.Errorf("Invalid rune global options --root")
	}

	conn, err := dialAgentSocket(root, containerId)
	if err != nil {
		return nil, err
	}

	isProductEnclave := sgx.DebugEnclave
	if strings.EqualFold(raParameters[constants.EnvKeyIsProductEnclave], "true") {
		isProductEnclave = sgx.ProductEnclave
	}

	raEpidQuoteType := QuoteSignatureTypeUnlinkable
	if strings.EqualFold(raParameters[constants.EnvKeyRaEpidIsLinkable], "true") {
		raEpidQuoteType = QuoteSignatureTypeLinkable
	}

	req := &pb.AgentServiceRequest{}
	req.Attest = &pb.AgentServiceRequest_Attest{
		Spid:            raParameters[constants.EnvKeyRaEpidSpid],
		SubscriptionKey: raParameters[constants.EnvKeyRaEpidSubKey],
		Product:         (uint32)(isProductEnclave),
		QuoteType:       (uint32)(raEpidQuoteType),
	}

	if err = protoBufWrite(conn, req); err != nil {
		return nil, err
	}

	logrus.Infof("Begin remote attestation")

	resp := &pb.AgentServiceResponse{}
	if err = protoBufRead(conn, resp); err != nil {
		return nil, err
	}

	logrus.Infof("End remote attestation")

	if resp.Attest.Error != "" {
		err = fmt.Errorf(resp.Attest.Error)
		return nil, err
	}

	iasReport := make(map[string]string)

	iasReport["StatusCode"] = resp.Attest.StatusCode
	iasReport["Request-ID"] = resp.Attest.RequestID
	iasReport["X-Iasreport-Signature"] = resp.Attest.XIasreportSignature
	iasReport["X-Iasreport-Signing-Certificate"] = resp.Attest.XIasreportSigningCertificate
	iasReport["ContentLength"] = resp.Attest.ContentLength
	iasReport["Content-Type"] = resp.Attest.ContentType
	iasReport["Body"] = resp.Attest.Body

	return iasReport, nil
}
