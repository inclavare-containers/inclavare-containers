package utils

import (
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Md5File(t *testing.T) {
	f, err := ioutil.TempFile("/tmp", "test")
	assert.Nil(t, err)
	err = ioutil.WriteFile(f.Name(), []byte("Hello world!"), 0644)
	assert.Nil(t, err)
	m, err := Md5File(f.Name())
	assert.Nil(t, err)
	fmt.Print(m)
}
