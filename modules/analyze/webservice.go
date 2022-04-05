package analyze

import (
	"embed"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"text/template"

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

type UnionFS struct {
	filesystems []http.FileSystem
}

func (ufs *UnionFS) AddFS(newfs http.FileSystem) {
	ufs.filesystems = append(ufs.filesystems, newfs)
}

func (ufs UnionFS) Open(filename string) (fs.File, error) {
	for _, fs := range ufs.filesystems {
		if f, err := fs.Open(filename); err == nil {
			return f, nil
		}
	}
	return nil, os.ErrNotExist
}

type AddprefixFS struct {
	Prefix string
	FS     fs.FS
}

func (apfs AddprefixFS) Open(filename string) (fs.File, error) {
	return apfs.FS.Open(path.Join(apfs.Prefix, filename))
}

type handlerfunc func(*engine.Objects, http.ResponseWriter, *http.Request)

type webservice struct {
	quit   chan bool
	Router *mux.Router
	UnionFS
	Objs *engine.Objects
	srv  *http.Server

	AdditionalHeaders []string // Additional things to add to the main page
}

func NewWebservice() *webservice {
	ws := &webservice{
		quit:   make(chan bool),
		Router: mux.NewRouter(),
	}

	ws.AddFS(http.FS(AddprefixFS{"html/", embeddedassets}))

	// Add stock functions
	analysisfuncs(ws)

	return ws
}

func (w *webservice) QuitChan() <-chan bool {
	return w.quit
}

func (w *webservice) Start(bind string, objs *engine.Objects, localhtml []string) error {
	w.Objs = objs

	// Profiling
	w.Router.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)

	w.srv = &http.Server{
		Addr:    bind,
		Handler: w.Router,
	}

	if len(localhtml) != 0 {
		w.UnionFS = UnionFS{}
		for _, html := range localhtml {
			// Override embedded HTML if asked to
			if stat, err := os.Stat(html); err == nil && stat.IsDir() {
				// Use local files if they exist
				log.Info().Msgf("Adding local HTML folder %v", html)
				if osf, err := osfs.NewFS(); err == nil {
					err = osf.Chdir(html)
					if err != nil {
						return errors.Wrap(err, "")
					}

					overrideassets, err := gofs.NewFs(osf)
					if err != nil {
						return errors.Wrap(err, "")
					}
					w.AddFS(http.FS(overrideassets))
				}
			} else {
				log.Fatal().Msgf("Could not add local HTML folder %v, failure: %v", html, err)
			}
		}
	}

	w.Router.Path("/").HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		indexfile, err := w.UnionFS.Open("index.html")
		if err != nil {
			log.Fatal().Msgf("Could not open index.html: %v", err)
		}
		rawindex, _ := ioutil.ReadAll(indexfile)
		indextemplate := template.Must(template.New("index").Parse(string(rawindex)))

		indextemplate.Execute(rw, struct {
			AdditionalHeaders []string
		}{
			AdditionalHeaders: w.AdditionalHeaders,
		})
	})
	w.Router.PathPrefix("/").Handler(http.FileServer(http.FS(w.UnionFS)))

	go func() {
		if err := w.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Msgf("Problem launching webservice listener: %s", err)
		}
	}()

	log.Info().Msgf("Listening - navigate to %v ... (ctrl-c or similar to quit)", bind)

	return nil
}
