package attestation // import "github.com/inclavare-containers/rune/libenclave/attestation"

import (
	"encoding/binary"
	"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"math/rand"
	"time"
)

// FIXME: how to make seed non-global?
type Nonce struct {
	seed    uint64
	timeout uint64
	// FIXME: use sync.mutex
}

func (n *Nonce) Generate() []byte {
	timestamp := uint64(time.Now().UnixNano())
	if n.seed+n.timeout >= timestamp {
		n.seed = timestamp
	}

	buf := make([]byte, intelsgx.NonceLength)
	binary.LittleEndian.PutUint64(buf, rand.Uint64())
	binary.LittleEndian.PutUint64(buf[intelsgx.NonceLength/2:], rand.Uint64())

	return buf
}
