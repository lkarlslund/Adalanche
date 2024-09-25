package analyze

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/lkarlslund/adalanche/modules/cli"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/spf13/cobra"
)

var (
	Command = &cobra.Command{
		Use:   "analyze [-options]",
		Short: "Lanunches the interactive discovery tool in your browser",
	}

	Bind        = Command.Flags().String("bind", "127.0.0.1:8080", "Address and port of webservice to bind to")
	NoBrowser   = Command.Flags().Bool("nobrowser", false, "Don't launch browser after starting webservice")
	LocalHTML   = Command.Flags().StringSlice("localhtml", nil, "Override embedded HTML and use a local folders for webservice (for development)")
	Certificate = Command.Flags().String("certificate", "", "Path to certificate file")
	PrivateKey  = Command.Flags().String("privatekey", "", "Path to private key file")
)

func init() {
	cli.Root.AddCommand(Command)
	if Command.RunE == nil { // Avoid colliding with enterprise version
		Command.RunE = Execute
	}
	Command.Flags().Lookup("localhtml").Hidden = true
}

func Execute(cmd *cobra.Command, args []string) error {
	datapath := *cli.Datapath

	if *Certificate != "" && *PrivateKey == "" {
		AddOption(WithCert(*Certificate, *PrivateKey))
	}

	// allow debug runs to use local paths for html
	for _, localhtmlpath := range *LocalHTML {
		AddOption(WithLocalHTML(localhtmlpath))
	}

	// Fire up the web interface with incomplete results
	ws := NewWebservice()

	err := ws.Start(*Bind)
	if err != nil {
		return err
	}

	// Launch browser
	if !*NoBrowser {
		var err error
		url := ws.protocol + "://" + *Bind
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

	err = ws.Analyze(datapath)
	if err != nil {
		return err
	}

	// Wait for webservice to end
	<-ws.QuitChan()
	return nil
}
