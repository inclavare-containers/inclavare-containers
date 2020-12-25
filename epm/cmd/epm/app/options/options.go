package options

import (
	"errors"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/inclavare-containers/epm/config"
	"github.com/spf13/pflag"
)

// Options containers the options of epm
type Options struct {
	// ConfigFile represents the absolute path of the epm configuration file
	ConfigFile string
}

func (opts *Options) AddFlags(fs *pflag.FlagSet) {
	if opts == nil {
		return
	}

	fs.StringVar(&opts.ConfigFile, "config", "/etc/epm/config.toml", "Path to the epm config file to be used.")
}

// ApplyTo loads the epm configuration file to the config.Config Object
func (opts *Options) ApplyTo(cfg *config.Config) error {
	if opts == nil {
		return errors.New("options is nil")
	}
	if _, err := toml.DecodeFile(opts.ConfigFile, cfg); err != nil {
		return fmt.Errorf("decode configuration failed. error: %++v", err)
	}
	return nil
}
