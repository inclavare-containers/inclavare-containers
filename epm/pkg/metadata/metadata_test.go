package metadata

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_GetCache(t *testing.T) {
	db := "/tmp/test.db"
	m, err := NewMetadataServer(db, time.Second*5)
	assert.Equal(t, err, nil)
	defer m.Close()
	c, err := m.GetCache("b1", "k1")
	assert.Equal(t, err, nil)
	assert.True(t, c == nil)
}
