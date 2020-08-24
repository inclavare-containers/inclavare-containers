package config

import (
	"fmt"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestDecodeConfig(t *testing.T) {
	text := `
root = "/var/local/epm"

[grpc]
  address = "/var/run/containerd/containerd.sock"
  uid = 0
  gid = 0
  max_recv_message_size = 16777216
  max_send_message_size = 16777216

[cache_pools]
  [cache_pools.bundle-cache-pool_occlum_cache0]
    type = "bundle-cache-pool.occlum.cache0"
  [cache_pools.bundle-cache-pool_occlum_cache1]
    type = "bundle-cache-pool.occlum.cache1"
  [cache_pools.bundle-cache-pool_occlum_cache2]
    type = "bundle-cache-pool.occlum.cache2"
`

	var cfg Config
	if _, err := toml.Decode(text, &cfg); err != nil {
		t.Fatal(err)
	}

	for k, v := range cfg.CachePools {
		fmt.Println(k)
		fmt.Println(v.Type)
	}

	fmt.Printf("%#v", cfg)
}
