package collect

import (
	"github.com/lkarlslund/adalanche/modules/cli"
	"github.com/spf13/cobra"
)

var (
	Collect = &cobra.Command{
		Use:   "collect",
		Short: "collect modules for various platforms (try \"adalanche help dump\")",
	}
)

func init() {
	cli.Root.AddCommand(Collect)
}
