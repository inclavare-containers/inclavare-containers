package client

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/inclavare-containers/shim/runtime/signature/types"
	"k8s.io/klog/v2"
)

type SignStandard string

const (
	PKCS1 SignStandard = "pkcs1"
)

// Client
type Client interface {
	Sign(data []byte) (signature []byte, publicKey []byte, err error)
	GetStandard() SignStandard
	GetPublicKey() (publicKey []byte, err error)
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
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Post(url, "text/plain", bytes.NewBuffer(data))
	if err != nil || resp.StatusCode != 200 {
		klog.Errorf("request sign error,%v", err)
		return nil, nil, err
	}
	defer resp.Body.Close()
	signedBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		klog.Errorf("failed to read sign response,%v", err)
		return nil, nil, err
	}
	payload := &types.SignaturePayload{}
	if err := json.Unmarshal(signedBytes, payload); err != nil {
		klog.Errorf("failed to unmarshal sign response,%v", err)
		return nil, nil, err
	}
	decode, err := base64.StdEncoding.DecodeString(payload.Signature)
	if err != nil {
		klog.Errorf("failed to decode signature,%v", err)
		return nil, nil, err
	}
	return decode, []byte(payload.PublicKey), nil
}

func (c *pkcs1Client) GetPublicKey() (publicKey []byte, err error) {
	var subURI = "public-key"
	var url string
	if strings.HasSuffix(c.serviceBaseURL.String(), "/") {
		url = fmt.Sprintf("%s%s", c.serviceBaseURL.String(), string(subURI))
	} else {
		url = fmt.Sprintf("%s/%s", c.serviceBaseURL.String(), string(subURI))
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(url)
	defer resp.Body.Close()
	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		klog.Errorf("failed to read public key response,%v", err)
		return nil, err
	}
	return bytes, nil
}

func (c *pkcs1Client) GetStandard() SignStandard {
	return PKCS1
}
