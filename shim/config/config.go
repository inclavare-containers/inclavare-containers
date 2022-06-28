package config

type Containerd struct {
	Socket                 string `toml:"socket"`
	AgentContainerInstance string `toml:"agent_container_instance"`
	AgentContainerRootDir  string `toml:"agent_container_root_dir"`
	AgentUrl               string `toml:"agent_url"`
}

type Config struct {
	LogLevel   string     `toml:"log_level"`
	Containerd Containerd `toml:"containerd"`
}
