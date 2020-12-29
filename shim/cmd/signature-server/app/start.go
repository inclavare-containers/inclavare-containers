package app

import (
	"github.com/spf13/cobra"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/inclavare-containers/shim/cmd/signature-server/app/options"
)

func NewSignatureServer(stopCh <-chan struct{}) *cobra.Command {
	opts := options.NewSignatureServerOptions()
	cmd := &cobra.Command{
		Short: "Launch signature server",
		Long:  "Launch signature server",
		RunE: func(cmd *cobra.Command, args []string) error {
			errs := opts.Validate()
			if err := utilerrors.NewAggregate(errs); err != nil {
				return err
			}
			return runServer(opts, stopCh)
		},
	}
	flags := cmd.Flags()
	opts.AddFlags(flags)
	return cmd
}
