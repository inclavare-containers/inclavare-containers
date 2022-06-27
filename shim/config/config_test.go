package config

import (
	"fmt"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestDecodeConfig(t *testing.T) {
	text := `log_level = "debug" # "debug" "info" "warn" "error"

[containerd]
    socket = "/run/containerd/containerd.sock"
`

	var cfg Config
	if _, err := toml.Decode(text, &cfg); err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%#v", cfg)
}
