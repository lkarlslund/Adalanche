package collect

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lkarlslund/adalanche/modules/cli"
	clicollect "github.com/lkarlslund/adalanche/modules/cli/collect"
	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/spf13/cobra"
)

var (
	Cmd = &cobra.Command{
		Use:   "localmachine",
		Short: "Gathers local information about a machine in the network (deploy with a sch.task via GPO for efficiency)",
		RunE:  Execute,
	}
)

func init() {
	clicollect.Collect.AddCommand(Cmd)
}

func Execute(cmd *cobra.Command, args []string) error {
	if err := clicollect.ValidateFormat(); err != nil {
		return err
	}
	datapath := *cli.Datapath

	err := os.MkdirAll(datapath, 0700)
	if err != nil {
		return fmt.Errorf("problem accessing output folder: %v", err)
	}

	info, err := Collect()
	if err != nil {
		return err
	}
	WriteAssessmentSummary(cmd.ErrOrStderr(), &info)

	targetname := info.Machine.Name + localmachine.Suffix
	if info.Machine.IsDomainJoined {
		targetname = info.Machine.Name + "$" + info.Machine.Domain + localmachine.Suffix
	}
	if *clicollect.CollectionFormat == "v2" {
		targetname = targetname[:len(targetname)-len(localmachine.Suffix)] + collection.MachineSuffix
		outputfile := filepath.Join(datapath, targetname)
		// Machine collections run on many hosts into shared folders, so they
		// write no run manifests.
		if err := localmachine.WriteCollection(outputfile, info, nil, clicollect.OutputOptions()...); err != nil {
			return fmt.Errorf("problem writing to file %v: %w", outputfile, err)
		}
		ui.Info().Msgf("Information collected to file %v", outputfile)
		return nil
	}
	output, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("problem marshalling JSON: %v", err)
	}

	outputfile := filepath.Join(datapath, targetname)
	err = clicollect.WriteFileAtomic(outputfile, func(w io.Writer) error {
		_, err := w.Write(output)
		return err
	})
	if err != nil {
		return fmt.Errorf("problem writing to file %v: %v", outputfile, err)
	}
	ui.Info().Msgf("Information collected to file %v", outputfile)
	return nil
}
