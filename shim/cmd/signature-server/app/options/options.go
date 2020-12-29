package options

import (
	"errors"

	"github.com/spf13/pflag"

	"github.com/inclavare-containers/shim/runtime/signature/server/conf"
)

type SignatureServerOptions struct {
	PrivateKeyPath string
	PublicKeyPath  string
	//CertificatePath string
}

func NewSignatureServerOptions() *SignatureServerOptions {
	return &SignatureServerOptions{}
}

func (opts *SignatureServerOptions) Validate() []error {
	if opts == nil {
		return nil
	}
	var allErrors []error
	if opts.PrivateKeyPath == "" {
		allErrors = append(allErrors, errors.New("--private-key cannot be empty"))
	}
	if opts.PublicKeyPath == "" {
		allErrors = append(allErrors, errors.New("--public-key cannot be empty"))
	}
	return allErrors
}

func (opts *SignatureServerOptions) AddFlags(fs *pflag.FlagSet) {
	if opts == nil {
		return
	}
	fs.StringVar(&opts.PrivateKeyPath, "private-key", "/etc/signature/pki/privatekey.pem", "private key path")
	fs.StringVar(&opts.PublicKeyPath, "public-key", "/etc/signature/pki/publickey.pem", "public key path")

}

func (opts *SignatureServerOptions) ApplyTo(cfg *conf.Config) error {
	if opts == nil {
		return errors.New("ToolkitServerOptions is nil")
	}
	cfg.PrivateKeyPath = opts.PrivateKeyPath
	cfg.PublicKeyPath = opts.PublicKeyPath
	return nil
}
