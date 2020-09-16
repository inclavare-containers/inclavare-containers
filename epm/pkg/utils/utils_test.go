package utils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_DirSize(t *testing.T) {
	size, err := DirSize("/tmp/")
	assert.Nil(t, err)
	fmt.Println(size)
}
