package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/alibaba/inclavare-containers/shim/runtime/signature/types"

	"github.com/golang/glog"
)

type SignStandard string

const (
	PKCS1 SignStandard = "pkcs1"
)

// Client
type Client interface {
	Sign(data []byte) (signature []byte, publicKey []byte, err error)
	GetStandard() SignStandard
}

//var _ Client = &pkcs1Client{}

type pkcs1Client struct {
	internalClient *http.Client
	serviceBaseURL *url.URL
	standard       SignStandard
}

func NewClient(standard SignStandard, serviceBaseURL *url.URL) Client {
	switch standard {
	case PKCS1:
		return &pkcs1Client{
			serviceBaseURL: serviceBaseURL,
			standard:       PKCS1,
		}
	default:
		return &pkcs1Client{
			serviceBaseURL: serviceBaseURL,
			standard:       PKCS1,
		}
	}
}

func (c *pkcs1Client) init() {
	c.internalClient = &http.Client{
		Transport: &http.Transport{
			//TODO: verify server
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func (c *pkcs1Client) Sign(data []byte) (signature []byte, publicKey []byte, err error) {
	if c.internalClient == nil {
		c.init()
	}
	var url string
	if strings.HasSuffix(c.serviceBaseURL.String(), "/") {
		url = fmt.Sprintf("%s%s", c.serviceBaseURL.String(), string(c.standard))
	} else {
		url = fmt.Sprintf("%s/%s", c.serviceBaseURL.String(), string(c.standard))
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		glog.Errorf("failed to new sign request, %v", err)
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := c.internalClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		glog.Errorf("request sign error,%v", err)
		return nil, nil, err
	}
	defer resp.Body.Close()
	signedBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		glog.Errorf("failed to read sign response,%v", err)
		return nil, nil, err
	}
	payload := &types.SignaturePayload{}
	if err := json.Unmarshal(signedBytes, payload); err != nil {
		glog.Errorf("failed to unmarshal sign response,%v", err)
		return nil, nil, err
	}
	return []byte(payload.Signature), []byte(payload.PublicKey), nil
}

func (c *pkcs1Client) GetStandard() SignStandard {
	return PKCS1
}
