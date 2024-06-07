package collect

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	clicollect "github.com/lkarlslund/adalanche/modules/cli/collect"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/spf13/cobra"
)

var (
	cmd = &cobra.Command{
		Use:   "localmachine",
		Short: "Gathers local information about a machine in the network (deploy with a sch.task via GPO for efficiency)",
		RunE:  Execute,
	}
)

func init() {
	clicollect.Collect.AddCommand(cmd)
}

func Execute(cmd *cobra.Command, args []string) error {
	var outputpath string
	if op := cmd.InheritedFlags().Lookup("datapath"); op != nil {
		outputpath = op.Value.String()
	}

	err := os.MkdirAll(outputpath, 0600)
	if err != nil {
		return fmt.Errorf("Problem accessing output folder: %v", err)
	}

	info, err := Collect()
	if err != nil {
		return err
	}

	if outputpath == "" {
		ui.Warn().Msg("Missing -outputpath parameter - writing file to current directory")
		outputpath = "."
	}

	targetname := info.Machine.Name + localmachine.Suffix
	if info.Machine.IsDomainJoined {
		targetname = info.Machine.Name + "$" + info.Machine.Domain + localmachine.Suffix
	}
	output, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("Problem marshalling JSON: %v", err)
	}

	outputfile := filepath.Join(outputpath, targetname)
	err = ioutil.WriteFile(outputfile, output, 0600)
	if err != nil {
		return fmt.Errorf("Problem writing to file %v: %v", outputfile, err)
	}
	ui.Info().Msgf("Information collected to file %v", outputfile)
	return nil
}
