package config

import (
	"fmt"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestDecodeConfig(t *testing.T) {
	text := `log_level = "debug" # "debug" "info" "warn" "error"

sgx_tool_sign = "/opt/intel/sgxsdk/bin/x64/sgx_sign"

[containerd]
    socket = "/run/containerd/containerd.sock"

[enclave_runtime]

    [enclave_runtime.occlum]
        build_image = "docker.io/occlum/occlum:0.12.0-ubuntu18.04"

    [enclave_runtime.graphene]
`

	var cfg Config
	if _, err := toml.Decode(text, &cfg); err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%#v", cfg)
}
