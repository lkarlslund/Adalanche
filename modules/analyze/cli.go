package analyze

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/lkarlslund/adalanche/modules/cli"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/ui"
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
	datapath := cmd.InheritedFlags().Lookup("datapath").Value.String()

	// Process what we can in foreground, and the rest in the background
	objs, err := engine.Run(datapath)
	if err != nil {
		return err
	}

	// Fire up the web interface with incomplete results
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
			ui.Warn().Msgf("Problem launching browser: %v", err)
		}
	}

	// Wait for webservice to end
	<-WebService.QuitChan()
	return nil
}
