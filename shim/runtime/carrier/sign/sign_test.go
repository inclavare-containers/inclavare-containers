package sign

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_RemoteSign(t *testing.T) {
	signingMaterial := "/tmp/test"
	ioutil.WriteFile(signingMaterial, []byte("hello"), 0644)
	publicKeyFile, signatureFile, err := RemoteSign(signingMaterial, "http://127.0.0.1:9080")
	assert.Nil(t, err)
	bytes, err := ioutil.ReadFile(publicKeyFile)
	assert.Nil(t, err)
	assert.NotEqual(t, 0, len(bytes))
	bytes, err = ioutil.ReadFile(signatureFile)
	assert.Nil(t, err)
	assert.NotEqual(t, 0, len(bytes))
	os.Remove(signingMaterial)
	os.RemoveAll(filepath.Dir(publicKeyFile))
}
