package cli

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime/debug"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/felixge/fgtrace"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/version"
	"github.com/spf13/cobra"
)

var (
	Root = &cobra.Command{
		Use:           "adalanche",
		Short:         version.VersionStringShort(),
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	loglevel     = Root.PersistentFlags().String("loglevel", "info", "Console log level")
	logfile      = Root.PersistentFlags().String("logfile", "", "File to log to")
	logfilelevel = Root.PersistentFlags().String("logfilelevel", "info", "Log file log level")

	embeddedprofiler  = Root.PersistentFlags().Bool("embeddedprofiler", false, "Start embedded Go profiler on localhost:6060")
	cpuprofile        = Root.PersistentFlags().Bool("cpuprofile", false, "Save CPU profile from start to end of processing in datapath")
	dofgtrace         = Root.PersistentFlags().Bool("fgtrace", false, "Save CPU trace start to end of processing in datapath")
	cpuprofiletimeout = Root.PersistentFlags().Int32("cpuprofiletimeout", 0, "CPU profiling timeout in seconds (0 means no timeout)")

	datapath = Root.PersistentFlags().String("datapath", "data", "folder to store and read data")

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

	ui.Info().Msg(version.VersionString())

	if *embeddedprofiler {
		go func() {
			err := http.ListenAndServe("localhost:6060", nil)
			if err != nil {
				ui.Error().Msgf("Profiling listener failed: %v", err)
			}
		}()
	}

	stopprofile := make(chan bool, 5)
	stopfgtrace := make(chan bool, 5)
	var profilewriters sync.WaitGroup

	if *dofgtrace {
		tracefile := filepath.Join(*datapath, "adalanche-fgtrace-"+time.Now().Format("06010215040506")+".json")
		trace := fgtrace.Config{Dst: fgtrace.File(tracefile)}.Trace()

		profilewriters.Add(1)

		go func() {
			<-stopfgtrace
			err = trace.Stop()
			if err != nil {
				ui.Error().Msgf("Problem stopping fgtrace: %v", err)
			}
			profilewriters.Done()
		}()

		if *cpuprofiletimeout > 0 {
			go func() {
				<-time.After(time.Second * (time.Duration(*cpuprofiletimeout)))
				stopfgtrace <- true
			}()
		}

	}

	if *cpuprofile {
		pproffile := filepath.Join(*datapath, "adalanche-cpuprofile-"+time.Now().Format("06010215040506")+".pprof")
		f, err := os.Create(pproffile)
		if err != nil {
			return fmt.Errorf("Could not set up CPU profiling in file %v: %v", pproffile, err)
		}
		pprof.StartCPUProfile(f)

		profilewriters.Add(1)

		go func() {
			<-stopprofile
			pprof.StopCPUProfile()
			profilewriters.Done()
		}()

		if *cpuprofiletimeout > 0 {
			go func() {
				<-time.After(time.Second * (time.Duration(*cpuprofiletimeout)))
				stopprofile <- true
			}()
		}
	}

	debug.SetGCPercent(10)

	// Ensure the data folder is available
	if _, err := os.Stat(*datapath); os.IsNotExist(err) {
		err = os.MkdirAll(*datapath, 0711)
		if err != nil {
			return fmt.Errorf("Could not create data folder %v: %v", datapath, err)
		}
	}

	err = Root.Execute()

	stopfgtrace <- true
	stopprofile <- true

	profilewriters.Wait()

	if err == nil {
		ui.Info().Msgf("Terminating successfully")
	}

	return err
}
