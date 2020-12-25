package config

import (
	"fmt"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestDecodeConfig(t *testing.T) {
	text := `
root = "/var/local/epm"
db_path = "/etc/epm/epm.db"
db_timeout = 10

[grpc]
  address = "/var/run/epm/epm.sock"
  uid = 0
  gid = 0
  max_recv_message_size = 16777216
  max_send_message_size = 16777216

[pools]
  [pools."bundle-cache.occlum.cache0"]
    type = "bundle-cache.occlum.cache0"
  [pools."bundle-cache.occlum.cache1"]
    type = "bundle-cache.occlum.cache1"
  [pools."bundle-cache.occlum.cache2"]
    type = "bundle-cache.occlum.cache2"
`

	var cfg Config
	if _, err := toml.Decode(text, &cfg); err != nil {
		t.Fatal(err)
	}

	for k, v := range cfg.EnclavePools {
		fmt.Println(k)
		fmt.Println(v.Type)
	}

	fmt.Printf("%#v", cfg)
}
