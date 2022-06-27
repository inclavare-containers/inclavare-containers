package config

type Containerd struct {
	Socket string `toml:"socket"`
}

type Config struct {
	LogLevel   string     `toml:"log_level"`
	Containerd Containerd `toml:"containerd"`
}
