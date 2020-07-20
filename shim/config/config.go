package config

type Containerd struct {
	Socket string `toml:"socket"`
}

type Signature struct {
	ServerAddress string `toml:"server_address"`
}

type Occlum struct {
	BuildImage         string `toml:"build_image"`
	EnclaveRuntimePath string `toml:"enclave_runtime_path"`
}

type Graphene struct {
}

type EnclaveRuntime struct {
	Occlum   Occlum   `toml:"occlum"`
	Graphene Graphene `toml:"graphene"`
}

type Config struct {
	LogLevel       string         `toml:"log_level"`
	SgxToolSign    string         `toml:"sgx_tool_sign"`
	Containerd     Containerd     `toml:"containerd"`
	Signature      Signature      `toml:"signature"`
	EnclaveRuntime EnclaveRuntime `toml:"enclave_runtime"`
}
