package analyze

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
	"path"

	"github.com/absfs/gofs"
	"github.com/absfs/osfs"
	"github.com/gorilla/mux"
	jsoniter "github.com/json-iterator/go"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

//go:embed html/*
var embeddedassets embed.FS

var (
	qjson = jsoniter.ConfigCompatibleWithStandardLibrary
)

type FSPrefix struct {
	Prefix string
	FS     fs.FS
}

func (f FSPrefix) Open(filename string) (fs.File, error) {
	return f.FS.Open(path.Join(f.Prefix, filename))
}

type webservice struct {
	quit   chan bool
	Router *mux.Router
	fs     fs.FS
	Objs   *engine.Objects
	srv    *http.Server
}

func NewWebservice() *webservice {
	ws := &webservice{
		quit:   make(chan bool),
		Router: mux.NewRouter(),
	}

	// Add stock functions
	analysisfuncs(ws)

	return ws
}

type handlerfunc func(*engine.Objects, http.ResponseWriter, *http.Request)

// func (ws *webservice) RegisterHandler(path string, hf handlerfunc) {
// 	ws.router.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
// 		hf(ws.objs, w, r)
// 	})
// }

func (w *webservice) QuitChan() <-chan bool {
	return w.quit
}

func (w *webservice) Start(bind string, objs *engine.Objects) error {
	w.Objs = objs

	w.srv = &http.Server{
		Addr:    bind,
		Handler: w.Router,
	}

	// Serve embedded static files, or from html folder if it exists
	var usinglocalhtml bool
	if *localhtml != "" {
		// Override embedded HTML if asked to
		if stat, err := os.Stat(*localhtml); err == nil && stat.IsDir() {
			// Use local files if they exist
			log.Info().Msgf("Switching from embedded HTML to local folder %v", *localhtml)
			if osf, err := osfs.NewFS(); err == nil {
				err = osf.Chdir(*localhtml) // Move up one folder, so we have html/ below us
				if err != nil {
					return errors.Wrap(err, "")
				}
				assets, err := gofs.NewFs(osf)
				if err != nil {
					return errors.Wrap(err, "")
				}
				w.Router.PathPrefix("/").Handler(http.FileServer(http.FS(FSPrefix{
					// Prefix: "html",
					FS: assets,
				})))
			}
			usinglocalhtml = true
		} else {
			log.Warn().Msgf("Not switching from embedded HTML to local folder %v, failure: %v", *localhtml, err)
		}
	}
	if !usinglocalhtml {
		w.Router.PathPrefix("/").Handler(http.FileServer(http.FS(FSPrefix{
			Prefix: "html",
			FS:     embeddedassets,
		})))
	}

	go func() {
		if err := w.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Msgf("Problem launching webservice listener: %s", err)
		}
	}()

	log.Info().Msgf("Listening - navigate to %v ... (ctrl-c or similar to quit)", bind)

	return nil
}
