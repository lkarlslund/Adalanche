package collect

import (
	"fmt"
	"os"

	"github.com/lkarlslund/adalanche/modules/collection"

	"github.com/lkarlslund/adalanche/modules/cli"
	"github.com/spf13/cobra"
)

var (
	Collect = &cobra.Command{
		Use:   "collect",
		Short: "collect modules for various platforms (try \"adalanche help dump\")",
	}
)

var (
	CollectionFormat = Collect.PersistentFlags().String("collectionformat", "v2", "Collection format: v2 or legacy")
	NoOverwrite      = Collect.PersistentFlags().Bool("nooverwrite", false, "Fail instead of replacing an existing output file")
)

// OutputOptions returns the container options for collection output files.
func OutputOptions() []collection.CreateOption {
	if *NoOverwrite {
		return nil
	}
	return []collection.CreateOption{collection.ReplaceExisting()}
}

// OutputFileFlags returns open flags for output written directly to its
// final name, honoring --nooverwrite.
func OutputFileFlags() int {
	if *NoOverwrite {
		return os.O_CREATE | os.O_EXCL | os.O_WRONLY
	}
	return os.O_CREATE | os.O_TRUNC | os.O_WRONLY
}

func ValidateFormat() error {
	if *CollectionFormat != "legacy" && *CollectionFormat != "v2" {
		return fmt.Errorf("unknown collection format %q; use v2 or legacy", *CollectionFormat)
	}
	return nil
}

func init() {
	cli.Root.AddCommand(Collect)
}

func StartRun(directory string, requested map[string]string) (*collection.Run, error) {
	if *CollectionFormat != "v2" {
		return nil, nil
	}
	return collection.StartRun(directory, requested)
}
