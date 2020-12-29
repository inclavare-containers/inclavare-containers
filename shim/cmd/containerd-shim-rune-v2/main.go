// +build linux

package main

import (
	"github.com/containerd/containerd/runtime/v2/shim"
	"github.com/inclavare-containers/shim/runtime/v2/rune/v2"
)

func main() {
	shim.Run("io.containerd.rune.v2", v2.New)
}
