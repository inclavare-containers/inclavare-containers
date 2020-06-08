package client

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_pkcs1Client_Sign(t *testing.T) {
	baseUrl, err := url.Parse("https://47.102.121.174:8443/api/v1/signature")
	assert.Nil(t, err)
	client := NewClient(PKCS1, baseUrl)
	signature, publicKey, err := client.Sign([]byte("Hello"))
	assert.Nil(t, err)
	t.Logf("%s\n%s\n", string(signature), string(publicKey))
}
