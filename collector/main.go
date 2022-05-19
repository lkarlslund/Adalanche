package main

import (
	"fmt"
	"os"

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
	debuglogging  = wrapcollector.Flags().Bool("debug", false, "Debug logging")
)

func init() {
	wrapcollector.RunE = Execute
}

func Execute(cmd *cobra.Command, args []string) error {
	if !*debuglogging {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Info().Msg("Debug logging enabled")
	}

	// Ensure the data folder is available
	if _, err := os.Stat(*datapath); os.IsNotExist(err) {
		err = os.MkdirAll(*datapath, 0711)
		if err != nil {
			return fmt.Errorf("Could not create data folder %v: %v", datapath, err)
		}
	}

	return collect.Collect(*datapath)
}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        colorable.NewColorableStdout(),
		TimeFormat: "15:04:05.06",
	})

	log.Info().Msg(version.VersionString())

	err := wrapcollector.Execute()
	if err != nil {
		log.Error().Err(err).Msg("Failed to execute")
	}
}
