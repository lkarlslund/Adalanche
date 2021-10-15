package main

import (
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine/collect"
	"github.com/lkarlslund/adalanche/modules/version"
	"github.com/mattn/go-colorable"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// This is a wrapper for the new style using AIO executable, for people using the collector
// You should move to the AIO version, using "adalanche collect", but for now the standalone collect
// binary is still available

var (
	wrapcollector = &cobra.Command{}
	datapath      = wrapcollector.Flags().String("outputpath", "", "Dump output JSON file in this folder")
)

func init() {
	wrapcollector.RunE = Execute
}

func Execute(cmd *cobra.Command, args []string) error {
	return collect.Collect(*datapath)
}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        colorable.NewColorableStdout(),
		TimeFormat: "15:04:05.06",
	})

	log.Info().Msgf("%v built %v commit %v", version.Programname, version.Builddate, version.Commit)
	log.Info().Msg(version.Copyright + ", " + version.Disclaimer)

	wrapcollector.Execute()
}
