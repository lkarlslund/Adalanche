package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lkarlslund/adalanche/modules/profiling"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/version"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	Root = &cobra.Command{
		Use:              "adalanche",
		Short:            version.VersionStringShort(),
		SilenceErrors:    true,
		SilenceUsage:     true,
		TraverseChildren: true,
	}
	prerunhooks []func(cmd *cobra.Command, args []string) error

	loglevel = Root.Flags().String("loglevel", "info", "Console log level")

	logfile      = Root.Flags().String("logfile", "", "File to log to")
	logfilelevel = Root.Flags().String("logfilelevel", "info", "Log file log level")
	logzerotime  = Root.Flags().Bool("logzerotime", false, "Logged timestamps start from zero when program launches")

	embeddedprofiler  = Root.Flags().Bool("embeddedprofiler", false, "Start embedded Go profiler on localhost:6060")
	flightRecorder    = Root.Flags().Bool("flightrecorder", false, "Keep a recent execution trace; requires embeddedprofiler")
	flightBytes       = Root.Flags().Uint64("flightrecorderbytes", 16<<20, "Trace window byte target, not a hard memory limit (1–256 MiB)")
	flightAge         = Root.Flags().Duration("flightrecorderage", 30*time.Second, "Desired trace history age (byte target takes precedence)")
	blockRate         = Root.Flags().Int("blockprofilerate", 0, "Blocking sample interval in nanoseconds; 0 disables, 1 samples all")
	mutexFraction     = Root.Flags().Int("mutexprofilefraction", 0, "Sample one in N mutex contention events; 0 disables")
	cpuprofile        = Root.Flags().Bool("cpuprofile", false, "Save CPU profile from start to end of processing in datapath")
	cpuprofiletimeout = Root.Flags().Int32("cpuprofiletimeout", 0, "CPU profiling timeout in seconds (0 means no timeout, -1 means stop when data processing ends)")
	memprofile        = Root.Flags().Bool("memprofile", false, "Save memory profile from start to end of processing in datapath")
	memprofiletimeout = Root.Flags().Int32("memprofiletimeout", 0, "Memory profiling timeout in seconds (0 means no timeout, -1 means stop when data processing ends)")
	dofgtrace         = Root.Flags().Bool("fgtrace", false, "Save CPU fgtrace start to end of processing in datapath")
	dofgprof          = Root.Flags().Bool("fgprof", false, "Save CPU fgprof start to end of processing in datapath")

	// also available for subcommands
	Datapath = Root.Flags().String("datapath", "data", "folder to store and read data")

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show adalanche version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			ui.Info().Msg(version.ProgramVersionShort())
			return nil
		},
	}

	OverrideArgs []string
)

func bindFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && viper.IsSet(f.Name) {
			if sv, ok := f.Value.(pflag.SliceValue); ok {
				sv.Replace(viper.GetStringSlice(f.Name))
			} else {
				f.Value.Set(viper.GetString(f.Name))
			}
		}
	})
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && viper.IsSet(f.Name) {
			if sv, ok := f.Value.(pflag.SliceValue); ok {
				sv.Replace(viper.GetStringSlice(f.Name))
			} else {
				f.Value.Set(viper.GetString(f.Name))
			}
		}
	})
	for _, subCommand := range cmd.Commands() {
		bindFlags(subCommand)
	}
}

func loadConfiguration(cmd *cobra.Command) {
	// Bind environment variables
	viper.SetEnvPrefix("ADALANCHE_")
	viper.AutomaticEnv()

	// Use config file from the flag.
	configfilename := filepath.Join(*Datapath, "configuration.yaml")
	viper.SetConfigFile(configfilename)
	if err := viper.ReadInConfig(); err == nil {
		ui.Info().Msgf("Using configuration file: %v", viper.ConfigFileUsed())
	} else {
		ui.Info().Msgf("No settings loaded from %v: %v", configfilename, err.Error())
	}

	bindFlags(cmd)
}

func init() {
	cobra.OnInitialize(func() {
		loadConfiguration(Root)
	})

	Root.AddCommand(versionCmd)
	Root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		ui.Zerotime = *logzerotime

		ll, err := ui.LogLevelString(*loglevel)
		if err != nil {
			ui.Error().Msgf("Invalid log level: %v - use one of: %v", *loglevel, ui.LogLevelStrings())
		} else {
			ui.SetLoglevel(ll)
		}

		if *logfile != "" {
			timestamp := time.Now().Format(time.DateOnly)
			*logfile = strings.Replace(*logfile, "{timestamp}", timestamp, 1)

			ll, err = ui.LogLevelString(*logfilelevel)
			if err != nil {
				ui.Error().Msgf("Invalid log file log level: %v - use one of: %v", *logfilelevel, ui.LogLevelStrings())
			} else {
				ui.SetLogFile(*logfile, ll)
			}
		} else {
			ui.SetLogFile("", ui.LevelInfo) // Tell logger to stop buffering early output
		}

		ui.Info().Msg(version.VersionString())

		// Ensure the data folder is available
		if _, err := os.Stat(*Datapath); os.IsNotExist(err) {
			err = os.MkdirAll(*Datapath, 0711)
			if err != nil {
				return fmt.Errorf("could not create data folder %v: %v", Datapath, err)
			}
		}
		for _, prerunhook := range prerunhooks {
			err := prerunhook(cmd, args)
			if err != nil {
				return fmt.Errorf("prerun hook failed: %v", err)
			}
		}

		err = profiling.Start(profiling.Options{
			Datapath:             *Datapath,
			EmbeddedProfiler:     *embeddedprofiler,
			FlightRecorder:       *flightRecorder,
			FlightRecorderBytes:  *flightBytes,
			FlightRecorderAge:    *flightAge,
			BlockProfileRate:     *blockRate,
			MutexProfileFraction: *mutexFraction,
			CPUProfile:           *cpuprofile,
			CPUProfileTimeout:    *cpuprofiletimeout,
			MemProfile:           *memprofile,
			MemProfileTimeout:    *memprofiletimeout,
			FGTrace:              *dofgtrace,
			FGProf:               *dofgprof,
		})
		if err != nil {
			return err
		}

		return nil
	}
	Root.PersistentPostRunE = func(cmd *cobra.Command, args []string) error {
		profiling.StopAll()
		return nil
	}
}

func AddPreRunHook(f func(cmd *cobra.Command, args []string) error) {
	prerunhooks = append(prerunhooks, f)
}

func CliMainEntryPoint() error {
	if len(os.Args[1:]) == 0 {
		Root.SetArgs(OverrideArgs)
	}

	err := Root.Execute()

	if err == nil {
		ui.Info().Msgf("Terminating successfully")
	}

	return err
}
