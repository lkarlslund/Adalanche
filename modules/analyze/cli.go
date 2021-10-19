package analyze

import (
	"fmt"
	"net/http"
	"os/exec"
	"runtime"

	"github.com/lkarlslund/adalanche/modules/cli"
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
	localhtml = Command.Flags().String("localhtml", "", "Override embedded HTML and use a local folder for webservice (for development)")
)

func init() {
	cli.Root.AddCommand(Command)
	Command.RunE = Execute
	Command.Flags().Lookup("localhtml").Hidden = true
}

func Execute(cmd *cobra.Command, args []string) error {
	datapath := cmd.InheritedFlags().Lookup("datapath").Value.String()

	objs, err := engine.Run(datapath)
	if err != nil {
		return err
	}

	/*
		switch command {
		case "schemagraph":
			gv := gographviz.NewEscape()
			gv.SetName("schema")
			gv.SetDir(true)
			// gv.AddSubGraph("schema", "attributes", nil)
			// gv.AddSubGraph("schema", "classes", nil)
			// gv.AddSubGraph("schema", "rights", nil)

			log.Info().Msg("Exporting schema graph in Graphviz format ...")

			output, err := os.Create("schemagraph.dot")
			if err != nil {
				log.Fatal().Msgf("Error opening output file: %v", err)
			}

			for _, object := range objs.Slice() {
				switch object.Type() {
				case engine.ObjectTypeAttributeSchema:
					// gv.AddNode("schema", object.IDString(), map[string]string{"label": object.OneAttrString(LDAPDisplayName)})

					// // Part of attribute set?
					// if as := object.OneAttr(AttributeSecurityGUID); as != nil {
					// 	if rg, found := engine.AllObjects.Find(RightsGUID, as); found {
					// 		// _ = rg
					// 		gv.AddEdge(object.IDString(), rg.IDString(), true, map[string]string{"label": "Part of"})
					// 	}
					// }

					//
				case engine.ObjectTypeClassSchema:
					gv.AddNode("schema", object.IDString(), map[string]string{"label": object.OneAttrString(engine.LDAPDisplayName)})

					// Possible superiors
					for _, psup := range object.Attr(engine.PossSuperiors).Slice() {
						if sup, found := objs.Find(engine.LDAPDisplayName, psup); found {
							// _ = sup
							gv.AddEdge(sup.IDString(), object.IDString(), true, map[string]string{"label": "Superior"})
						}
					}

					// // Must contain
					// for _, pcontain := range object.Attr(SystemMustContain).Slice() {
					// 	if contain, found := engine.AllObjects.Find(LDAPDisplayName, pcontain); found {
					// 		// _ = contain
					// 		gv.AddEdge(object.IDString(), contain.IDString(), true, map[string]string{"label": "Must"})
					// 	}
					// }

					// // May contain
					// for _, pcontain := range object.Attr(SystemMayContain).Slice() {
					// 	if contain, found := engine.AllObjects.Find(LDAPDisplayName, pcontain); found {
					// 		// _ = contain
					// 		gv.AddEdge(object.IDString(), contain.IDString(), true, map[string]string{"label": "May"})
					// 	}
					// }

				case engine.ObjectTypeControlAccessRight:
					gv.AddNode("schema", object.IDString(), map[string]string{"label": object.OneAttrString(engine.DisplayName)})
				}
			}
			output.WriteString(gv.String())
			output.Close()

			log.Info().Msg("Done")
		case "exportobjectsdebug":
			log.Info().Msg("Finding most valuable assets ...")

			output, err := os.Create("debug.txt")
			if err != nil {
				log.Fatal().Msgf("Error opening output file: %v", err)
			}

			for _, object := range objs.Slice() {
				fmt.Fprintf(output, "Object:\n%v\n\n-----------------------------\n", object)
			}
			output.Close()

			log.Info().Msg("Done")
		case "export":
			log.Info().Msg("Finding most valuable assets ...")
			q, err := ldapquery.ParseQueryStrict(*analyzequery, objs)
			if err != nil {
				log.Fatal().Msgf("Error parsing LDAP query: %v", err)
			}

			includeobjects := objs.Filter(func(o *engine.Object) bool {
				return q.Evaluate(o)
			})

			opts := engine.NewAnalyzeObjectsOptions()
			opts.IncludeObjects = includeobjects
			opts.Reverse = *exportinverted

			resultgraph := engine.AnalyzeObjects(opts)

			switch *exporttype {
			case "graphviz":
				err = ExportGraphViz(resultgraph, "adalanche-"+*domain+".dot")
			case "cytoscapejs":
				err = ExportCytoscapeJS(resultgraph, "adalanche-cytoscape-js-"+*domain+".json")
			default:
				log.Error().Msg("Unknown export format")
				showUsage()
			}
			if err != nil {
				log.Fatal().Msgf("Problem exporting graph: %v", err)
			}

			log.Info().Msg("Done")
		case "analyze", "dump-analyze":
		default:
			log.Error().Msgf("Unknown command %v", flag.Arg(0))
			showUsage()
		}
	*/

	quit := make(chan bool)

	srv, err := webservice(*bind, quit, objs)
	if err != nil {
		return err
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Msgf("Problem launching webservice listener: %s", err)
		}
	}()

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
	<-quit
	return nil
}
