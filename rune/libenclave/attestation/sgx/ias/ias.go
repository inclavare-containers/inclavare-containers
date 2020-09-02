package ias // import "github.com/opencontainers/runc/libenclave/attestation/sgx/ias"

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	attest "github.com/opencontainers/runc/libenclave/attestation"
	pb "github.com/opencontainers/runc/libenclave/attestation/proto"
	"github.com/opencontainers/runc/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
	"io"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"unsafe"
)

const (
	spidLength            = 16
	subscriptionKeyLength = 16
)

type reportStatus struct {
	requestId   string
	reportId    string
	timestamp   string
	quoteStatus string
}

type iasRegistry struct {
}

type iasService struct {
	attest.Service
	reportApiUrl    string
	spid            [spidLength]byte
	subscriptionKey [subscriptionKeyLength]byte
}

func (reg *iasRegistry) Create(p map[string]string) (*attest.Service, error) {
	isProduct := false
	v := attest.GetParameter("service-class", p)
	if v != "" && v == "product" {
		isProduct = true
	}

	spid := attest.GetParameter("spid", p)
	if spid == "" {
		return nil, fmt.Errorf("Missing parameter spid")
	}

	if len(spid) != spidLength*2 {
		return nil, fmt.Errorf("The length of spid must be %d-character",
			spidLength*2)
	}

	subKey := attest.GetParameter("subscription-key", p)
	if subKey == "" {
		return nil, fmt.Errorf("Missing parameter subscription-key")
	}

	if len(subKey) != subscriptionKeyLength*2 {
		return nil, fmt.Errorf("The length of subscription key must be %d-character",
			subscriptionKeyLength*2)
	}

	var rawSubKey []byte
	var err error
	if rawSubKey, err = hex.DecodeString(subKey); err != nil {
		return nil, fmt.Errorf("Failed to decode subscription key: %s", err)
	}

	var rawSpid []byte
	if rawSpid, err = hex.DecodeString(spid); err != nil {
		return nil, fmt.Errorf("Failed to decode spid: %s", err)
	}

	url := "https://api.trustedservices.intel.com/sgx"
	if !isProduct {
		url += "/dev"
	}

	apiVer := attest.GetParameter("apiVer", p)
	if apiVer != "" {
		apiVersion, err = strconv.ParseUint(apiVer, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("Invalid IAS API Version: %s", err)
		} else if apiVersion != apiV3 && apiVersion != apiV4 {
			return nil, fmt.Errorf("Unsupported IAS API Version: %s", apiVer)
		}
	}
	url += fmt.Sprintf("/attestation/v%d/report", apiVersion)

	ias := &iasService{
		reportApiUrl: url,
	}
	copy(ias.subscriptionKey[:], rawSubKey)
	copy(ias.spid[:], rawSpid)

	ias.Attester = ias

	return &ias.Service, nil
}

func (ias *iasService) PrepareChallenge() (*pb.AttestChallenge, error) {
	return &pb.AttestChallenge{
		Nonce: ias.NonceForChallenge.Generate(),
	}, nil
}

func (ias *iasService) HandleChallengeResponse(r *pb.AttestResponse) (*attest.Quote, error) {
	quote := r.GetQuote()

	if len(quote) <= intelsgx.QuoteLength {
		return nil, fmt.Errorf("Invalid length of quote returned: %d-byte", len(quote))
	}

	return &attest.Quote{Evidence: quote}, nil
}

// TODO: check target enclave report
func (ias *iasService) Check(q []byte) error {
	quote := (*intelsgx.Quote)(unsafe.Pointer(&q[0]))

	if ias.IsVerbose() {
		logrus.Infof("Target Platform's Quote")
		logrus.Infof("  Quote Body")
		logrus.Infof("    QUOTE Structure Version:                               %d",
			quote.Version)
		logrus.Infof("    EPID Signature Type:                                   %d",
			quote.SignatureType)
		logrus.Infof("    Platform's EPID Group ID:                              %#08x",
			quote.Gid)
		logrus.Infof("    Quoting Enclave's ISV assigned SVN:                    %#04x",
			quote.ISVSvnQe)
		logrus.Infof("    Provisioning Certification Enclave's ISV assigned SVN: %#04x",
			quote.ISVSvnPce)
		logrus.Infof("    EPID Basename:                                         0x%v",
			hex.EncodeToString(quote.Basename[:]))
		logrus.Infof("  Report Body")
		logrus.Infof("    Target CPU SVN:                                        0x%v",
			hex.EncodeToString(quote.CpuSvn[:]))
		logrus.Infof("    Enclave Misc Select:                                   %#08x",
			quote.MiscSelect)
		logrus.Infof("    Enclave Attributes:                                    0x%v",
			hex.EncodeToString(quote.Attributes[:]))
		logrus.Infof("    Enclave Hash:                                          0x%v",
			hex.EncodeToString(quote.MrEnclave[:]))
		logrus.Infof("    Enclave Signer:                                        0x%v",
			hex.EncodeToString(quote.MrSigner[:]))
		logrus.Infof("    ISV assigned Product ID:                               %#04x",
			quote.IsvProdId)
		logrus.Infof("    ISV assigned SVN:                                      %#04x",
			quote.IsvSvn)
		logrus.Infof("    Report Data:                                           0x%v...",
			hex.EncodeToString(quote.ReportData[:32]))
		logrus.Infof("  Encrypted EPID Signature")
		logrus.Infof("    Length:                                                %d",
			quote.SigLen)
		logrus.Infof("    Signature:                                             0x%v...",
			hex.EncodeToString(q[intelsgx.QuoteLength:intelsgx.QuoteLength+32]))
	}

	if quote.Version != intelsgx.QuoteVersion {
		return fmt.Errorf("Invalid quote version: %d", quote.Version)
	}

	if quote.SignatureType != intelsgx.QuoteSignatureTypeUnlinkable &&
		quote.SignatureType != intelsgx.QuoteSignatureTypeLinkable {
		return fmt.Errorf("Invalid signature type: %#04x", quote.SignatureType)
	}

	spid := [spidLength]byte{}
	copy(spid[:], quote.Basename[:spidLength])
	if spid != ias.spid {
		return fmt.Errorf("Invalid spid in quote body: 0x%v",
			hex.EncodeToString(quote.Basename[:]))
	}

	return nil
}

func (ias *iasService) getIasReport(quote []byte) (*attest.Status, map[string]string, error) {
	nonce := strconv.FormatUint(rand.Uint64(), 16) + strconv.FormatUint(rand.Uint64(), 16)
	p := &evidencePayload{
		IsvEnclaveQuote: base64.StdEncoding.EncodeToString(quote),
		PseManifest:     "",
		Nonce:           nonce,
	}

	status := &attest.Status{
		StatusCode:   attest.StatusSgxBit,
		ErrorMessage: "",
	}

	var resp *http.Response
	var err error
	if resp, err = ias.reportAttestationEvidence(p); err != nil {
		status.ErrorMessage = fmt.Sprintf("%s", err)
		return status, nil, err
	}
	defer resp.Body.Close()

	var reportStatus *reportStatus
	reportStatus, rawReport, err := checkVerificationReport(resp, quote, nonce)
	if err != nil {
		status.ErrorMessage = fmt.Sprintf("%s", err)
		return status, nil, err
	}

	iasReport := formatIasReport(resp, rawReport)

	status.SpecificStatus = reportStatus
	return status, iasReport, nil
}

func (ias *iasService) Verify(quote []byte) *attest.Status {
	status, _, err := ias.getIasReport(quote)
	if err != nil {
		return nil
	}

	return status
}

func (ias *iasService) GetVerifiedReport(quote []byte) (*attest.Status, map[string]string, error) {
	return ias.getIasReport(quote)
}

func (ias *iasService) ShowStatus(status *attest.Status) {
	s, ok := status.SpecificStatus.(*reportStatus)
	if ok {
		logrus.Infof("Request ID: %s\n", s.requestId)
		logrus.Infof("Report ID: %s\n", s.reportId)
		logrus.Infof("Timestamp: %s\n", s.timestamp)
		logrus.Infof("IsvEnclaveQuoteStatus: %s\n", s.quoteStatus)
	}
}

func (ias *iasService) reportAttestationEvidence(p *evidencePayload) (*http.Response, error) {
	var jp []byte
	var err error

	if jp, err = json.Marshal(p); err != nil {
		return nil, fmt.Errorf("Failed to marshal evidence payload: %s", err)
	}

	bjp := bytes.NewBuffer(jp)
	var req *http.Request
	if req, err = http.NewRequest(http.MethodPost, ias.reportApiUrl, bjp); err != nil {
		return nil, fmt.Errorf("Failed to create http.Request: %s", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Ocp-Apim-Subscription-Key", hex.EncodeToString(ias.subscriptionKey[:]))

	if ias.IsVerbose() {
		logrus.Infof("Initializing attestation evidence report ...")

		if dump, err := httputil.DumpRequestOut(req, true); err == nil {
			logrus.Infof("--- start of request ---")
			logrus.Infof("%s\n", dump)
			logrus.Infof("--- end of request ---")
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
		return nil, fmt.Errorf("Failed to send http request and receive http response: %s", err)
	}

	if ias.IsVerbose() {
		logrus.Infof("Attestation evidence response retrieved ...")

		if dump, err := httputil.DumpResponse(resp, true); err == nil {
			logrus.Infof("--- start of response ---")
			logrus.Infof("%s\n", dump)
			logrus.Infof("--- end of response ---")
		}
	}

	return resp, nil
}

func formatIasReport(resp *http.Response, rawReport string) map[string]string {
	iasReport := make(map[string]string)

	iasReport["Body"] = rawReport
	iasReport["StatusCode"] = strconv.FormatUint(uint64(resp.StatusCode), 10)
	iasReport["Request-ID"] = resp.Header.Get("Request-ID")
	iasReport["X-Iasreport-Signature"] = resp.Header.Get("X-Iasreport-Signature")
	iasReport["X-Iasreport-Signing-Certificate"] = resp.Header.Get("X-Iasreport-Signing-Certificate")
	iasReport["ContentLength"] = strconv.FormatUint(uint64(resp.ContentLength), 10)
	iasReport["Content-Type"] = resp.Header.Get("Content-Type")

	return iasReport
}

func checkVerificationReport(resp *http.Response, quote []byte, nonce string) (*reportStatus, string, error) {
	status := &reportStatus{
		requestId:   "",
		reportId:    "",
		quoteStatus: "",
	}

	if resp.StatusCode != 200 {
		errMsg := "Unexpected status"

		switch resp.StatusCode {
		case 400:
			errMsg = "Invalid Attestation Evidence Payload. The client should not repeat the request without modifications."
		case 401:
			errMsg = "Failed to authenticate or authorize request."
		case 500:
			errMsg = "Internal error occurred."
		case 503:
			errMsg = "IAS is currently not able to process the request due to a temporary overloading or maintenance. This is a temporary state and the same request can be repeated after some time."
		default:
		}

		return status, "", fmt.Errorf("%s: %s", resp.Status, errMsg)
	}

	reqId := resp.Header.Get("Request-ID")
	if reqId == "" {
		return status, "", fmt.Errorf("No Request-ID in response header")
	}

	status.requestId = reqId

	if resp.Header.Get("X-Iasreport-Signature") == "" {
		return status, "", fmt.Errorf("No X-Iasreport-Signature in response header")
	}

	if resp.Header.Get("X-Iasreport-Signing-Certificate") == "" {
		return status, "", fmt.Errorf("No X-Iasreport-Signing-Certificate in response header")
	}

	if resp.ContentLength == -1 {
		return status, "", fmt.Errorf("Unknown length of response body")
	}

	if resp.Header.Get("Content-Type") != "application/json" {
		return status, "", fmt.Errorf("Invalid content type (%s) in response",
			resp.Header.Get("Content-Type"))
	}

	var err error
	rawReport := make([]byte, resp.ContentLength)
	if _, err = io.ReadFull(resp.Body, rawReport); err != nil {
		return status, "", fmt.Errorf("Failed to read reponse body (%d-byte): %s",
			resp.ContentLength, err)
	}

	var report verificationReport
	if err = json.Unmarshal(rawReport, &report); err != nil {
		return status, "", fmt.Errorf("Failed to unmarshal attestation verification report: %s: %s",
			rawReport, err)
	}

	status.reportId = report.Id
	status.timestamp = report.Timestamp
	status.quoteStatus = report.IsvEnclaveQuoteStatus

	if report.Version != (uint32)(apiVersion) {
		return status, "", fmt.Errorf("Unsupported attestation API version %d in attesation verification report",
			report.Version)
	}

	if report.Nonce != nonce {
		return status, "", fmt.Errorf("Invalid nonce in attestation verification report: %s",
			report.Nonce)
	}

	if report.Id == "" || report.Timestamp == "" ||
		report.IsvEnclaveQuoteStatus == "" ||
		report.IsvEnclaveQuoteBody == "" {
		return status, "", fmt.Errorf("Required fields in attestation verification report is not present: %s",
			string(rawReport))
	}

	if report.IsvEnclaveQuoteStatus == "GROUP_OUT_OF_DATE" ||
		report.IsvEnclaveQuoteStatus == "CONFIGURATION_NEEDED" {
		if report.Version == apiV3 {
			if resp.Header.Get("Advisory-Ids") == "" || resp.Header.Get("Advisory-Url") == "" {
				return status, "", fmt.Errorf("Advisory-Ids or Advisory-Url is not present in response header")
			}
		} else if report.Version == apiV4 && (report.AdvisoryIds == "" || report.AdvisoryUrl == nil) {
			return status, "", fmt.Errorf("Advisory-Ids or Advisory-Url is not present in attestation verification report")
		}
	}

	var quoteBody []byte
	if quoteBody, err = base64.StdEncoding.DecodeString(report.IsvEnclaveQuoteBody); err != nil {
		return status, "", fmt.Errorf("Invalid isvEnclaveQuoteBody: %s",
			report.IsvEnclaveQuoteBody)
	}

	if len(quoteBody) != intelsgx.QuoteBodyLength+intelsgx.ReportBodyLength {
		return status, "", fmt.Errorf("Invalid length of isvEnclaveQuoteBody: %d-byte",
			len(quoteBody))
	}

	for i, v := range quoteBody {
		if v != quote[i] {
			return status, "", fmt.Errorf("Unexpected isvEnclaveQuoteBody: %s",
				report.IsvEnclaveQuoteBody)
		}
	}

	var sig []byte
	if sig, err = base64.StdEncoding.DecodeString(
		resp.Header.Get("X-Iasreport-Signature")); err != nil {
		return status, "", fmt.Errorf("Invalid X-Iasreport-Signature in response header: %s",
			resp.Header.Get("X-Iasreport-Signature"))
	}

	var pemCerts string
	if pemCerts, err = url.QueryUnescape(
		resp.Header.Get("X-Iasreport-Signing-Certificate")); err != nil {
		return status, "", fmt.Errorf("Failed to unescape X-Iasreport-Signing-Certificate in response header: %s: %s",
			resp.Header.Get("X-Iasreport-Signing-Certificate"), err)
	}

	rawPemCerts := []byte(pemCerts)
	rawPemCerts = append(rawPemCerts, caCert...)

	var derCerts []byte
	for true {
		var b *pem.Block

		if b, rawPemCerts = pem.Decode(rawPemCerts); err != nil {
			return status, "", fmt.Errorf("Failed to convert PEM certificate to DER format: %s: %s",
				pemCerts, err)
		}

		if b == nil {
			break
		}

		if b.Type != "CERTIFICATE" {
			return status, "", fmt.Errorf("Returned content is not PEM certificate: %s",
				b.Type)
		}

		derCerts = append(derCerts, b.Bytes...)
	}

	var x509Certs []*x509.Certificate
	if x509Certs, err = x509.ParseCertificates(derCerts); err != nil {
		return status, "", fmt.Errorf("Failed to parse certificates: %s", err)
	}

	cert := x509Certs[0]
	if err = cert.CheckSignature(x509.SHA256WithRSA, rawReport, sig); err != nil {
		return status, "", fmt.Errorf("Failed to verify the attestation verification report: %s",
			err)
	}

	for _, parentCert := range x509Certs[1:] {
		if err = cert.CheckSignatureFrom(parentCert); err != nil {
			return status, "", fmt.Errorf("Failed to verify the certificate (%s) with parent certificate (%s): %s",
				cert.Subject.String(), parentCert.Subject.String(), err)
		}

		cert = parentCert
	}

	return status, string(rawReport), nil
}

func init() {
	if err := attest.RegisterAttestation(&iasRegistry{}); err != nil {
		fmt.Print(err)
	}
}
