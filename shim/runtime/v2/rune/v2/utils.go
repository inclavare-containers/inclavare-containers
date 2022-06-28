package v2

import (
	"github.com/BurntSushi/toml"

	shim_config "github.com/inclavare-containers/shim/config"
	"github.com/inclavare-containers/shim/runtime/v2/rune/constants"
)

var (
	logLevel string
)

func parseConfig() error {
	var cfg shim_config.Config

	_, err := toml.DecodeFile(constants.ConfigurationPath, &cfg)
	if err != nil {
		return err
	}

	logLevel = cfg.LogLevel

	return nil
}
