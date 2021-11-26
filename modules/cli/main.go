package cli

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"runtime/pprof"
	"time"

	"github.com/lkarlslund/adalanche/modules/version"
	"github.com/mattn/go-colorable"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	Root = &cobra.Command{
		Use:           "adalanche",
		Short:         version.VersionStringShort(),
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	debuglogging     = Root.PersistentFlags().Bool("debug", false, "Enable debug logging")
	embeddedprofiler = Root.PersistentFlags().Bool("embeddedprofiler", false, "Start embedded Go profiler on localhost:6060")
	cpuprofile       = Root.PersistentFlags().Bool("cpuprofile", false, "Save CPU profile from start to end of processing in datapath")

	datapath = Root.PersistentFlags().String("datapath", "data", "folder to store and read data")

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show adalanche version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Info().Msg(version.ProgramVersionShort())
			return nil
		},
	}

	OverrideArgs []string
)

func init() {
	Root.AddCommand(versionCmd)
}

func Run() error {
	args := os.Args[1:]
	if len(args) == 0 {
		args = OverrideArgs
	}

	Root.SetArgs(args)
	Root.ParseFlags(args)

	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        colorable.NewColorableStdout(),
		TimeFormat: "15:04:05.06",
	})

	log.Info().Msg(version.VersionString())

	if *embeddedprofiler {
		go func() {
			err := http.ListenAndServe("localhost:6060", nil)
			if err != nil {
				log.Error().Msgf("Profiling listener failed: %v", err)
			}
		}()
	}

	if *cpuprofile {
		pproffile := filepath.Join(*datapath, "adalanche-cpuprofile-"+time.Now().Format("06010215040506")+".pprof")
		f, err := os.Create(pproffile)
		if err != nil {
			return fmt.Errorf("Could not set up CPU profiling in file %v: %v", pproffile, err)
		}
		pprof.StartCPUProfile(f)
	}

	if !*debuglogging {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Debug logging enabled")
	}

	// We do lots of allocations when importing stuff, so lets set this aggressively
	debug.SetGCPercent(10)

	// Ensure the data folder is available
	if _, err := os.Stat(*datapath); os.IsNotExist(err) {
		err = os.MkdirAll(*datapath, 0711)
		if err != nil {
			return fmt.Errorf("Could not create data folder %v: %v", datapath, err)
		}
	}

	err := Root.Execute()

	if *cpuprofile {
		pprof.StopCPUProfile()
	}

	if err == nil {
		log.Info().Msgf("Terminating successfully")
	}

	return err
}
