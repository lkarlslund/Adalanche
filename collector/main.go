package main

import (
	"fmt"
	"os"

	"github.com/lkarlslund/adalanche/modules/integrations/localmachine/collect"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/version"
	"github.com/spf13/cobra"
)

// This is a wrapper for the new style using AIO executable, for people using the collector
// You should move to the AIO version, using "adalanche collect", but for now the standalone collect
// binary is still available

var (
	wrapcollector = &cobra.Command{}
	datapath      = wrapcollector.Flags().String("outputpath", "", "Dump output JSON file in this folder")
	loglevel      = wrapcollector.Flags().String("loglevel", "info", "Console log level")
	logfile       = wrapcollector.Flags().String("logfile", "", "Log file")
	logfilelevel  = wrapcollector.Flags().String("logfilelevel", "info", "Log file log level")
)

func init() {
	wrapcollector.RunE = Execute
}

func Execute(cmd *cobra.Command, args []string) error {
	ll, err := ui.LogLevelString(*loglevel)
	if err != nil {
		ui.Error().Msgf("Invalid log level: %v - use one of: %v", *loglevel, ui.LogLevelStrings())
	} else {
		ui.SetDefaultLoglevel(ll)
	}

	if *logfile != "" {
		ll, err = ui.LogLevelString(*logfilelevel)
		if err != nil {
			ui.Error().Msgf("Invalid log file log level: %v - use one of: %v", *logfilelevel, ui.LogLevelStrings())
		} else {
			ui.SetLogFile(*logfile, ll)
		}
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
	ui.Info().Msg(version.VersionString())

	err := wrapcollector.Execute()
	if err != nil {
		ui.Error().Err(err).Msg("Failed to execute")
	}
}
