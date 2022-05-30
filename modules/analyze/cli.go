package analyze

import (
	"fmt"
	"os/exec"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/lkarlslund/adalanche/modules/cli"
	"github.com/lkarlslund/adalanche/modules/dedup"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	Command = &cobra.Command{
		Use:   "analyze [-options]",
		Short: "Lanunches the interactive discovery tool in your browser",
	}

	bind      = Command.Flags().String("bind", "127.0.0.1:8080", "Address and port of webservice to bind to")
	nobrowser = Command.Flags().Bool("nobrowser", false, "Don't launch browser after starting webservice")
	localhtml = Command.Flags().StringSlice("localhtml", nil, "Override embedded HTML and use a local folders for webservice (for development)")

	WebService = NewWebservice()
)

func init() {
	cli.Root.AddCommand(Command)
	Command.RunE = Execute
	Command.Flags().Lookup("localhtml").Hidden = true
}

func Execute(cmd *cobra.Command, args []string) error {
	starttime := time.Now()

	datapath := cmd.InheritedFlags().Lookup("datapath").Value.String()

	objs, err := engine.Run(datapath)
	if err != nil {
		return err
	}

	// After all this loading and merging, it's time to do release unused RAM
	debug.FreeOSMemory()

	log.Info().Msgf("Processing done in %v", time.Since(starttime))

	dedupStats := dedup.D.Statistics()

	log.Debug().Msgf("Deduplicator stats: %v items added using %v bytes in memory", dedupStats.ItemsAdded, dedupStats.BytesInMemory)
	log.Debug().Msgf("Deduplicator stats: %v items not allocated saving %v bytes of memory", dedupStats.ItemsSaved, dedupStats.BytesSaved)
	log.Debug().Msgf("Deduplicator stats: %v items removed (memory stats unavailable)", dedupStats.ItemsRemoved)
	log.Debug().Msgf("Deduplicator stats: %v collisions detected (first at %v objects)", dedupStats.Collisions, dedupStats.FirstCollisionDetected)
	log.Debug().Msgf("Deduplicator stats: %v keepalive objects added", dedupStats.KeepAliveItemsAdded)
	log.Debug().Msgf("Deduplicator stats: %v keepalive objects removed", dedupStats.KeepAliveItemsRemoved)

	// Try to recover some memory
	dedup.D.Flush()
	objs.DropIndexes()

	runtime.GC()
	debug.FreeOSMemory()

	err = WebService.Start(*bind, objs, *localhtml)
	if err != nil {
		return err
	}

	// Launch browser
	if !*nobrowser {
		var err error
		url := "http://" + *bind
		switch runtime.GOOS {
		case "linux":
			err = exec.Command("xdg-open", url).Start()
		case "windows":
			err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
		case "darwin":
			err = exec.Command("open", url).Start()
		default:
			err = fmt.Errorf("unsupported platform")
		}
		if err != nil {
			log.Warn().Msgf("Problem launching browser: %v", err)
		}
	}

	// Wait for webservice to end
	<-WebService.QuitChan()
	return nil
}
