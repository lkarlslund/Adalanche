package analyze

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"text/template"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	jsoniter "github.com/json-iterator/go"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/ui"
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

func (ufs UnionFS) Open(filename string) (http.File, error) {
	for _, fs := range ufs.filesystems {
		if f, err := fs.Open(filename); err == nil {
			return f, nil
		}
	}
	return nil, os.ErrNotExist
}

func (ufs UnionFS) Exists(prefix, filename string) bool {
	_, err := ufs.Open(filename)
	return err != os.ErrNotExist
}

type handlerfunc func(*engine.Objects, http.ResponseWriter, *http.Request)

type webservice struct {
	Initialized bool
	quit        chan bool

	srv    *http.Server
	Router *gin.Engine

	localhtmlused bool
	UnionFS

	status WebServiceStatus

	Objs *engine.Objects

	// srv *http.Server

	AdditionalHeaders []string // Additional things to add to the main page
}

func NewWebservice() *webservice {
	gin.SetMode(gin.ReleaseMode) // Has to happen first
	ws := &webservice{
		quit:   make(chan bool),
		Router: gin.New(),
	}
	ws.Router.Use(func(c *gin.Context) {
		start := time.Now() // Start timer
		path := c.Request.URL.Path

		// Process request
		c.Next()

		logger := ui.Info()
		if c.Writer.Status() >= 500 {
			logger = ui.Error()
		}

		logger.Msgf("%s %s (%v) %v, %v bytes", c.Request.Method, path, c.Writer.Status(), time.Since(start), c.Writer.Size())
	})
	ws.Router.Use(gin.Recovery()) // adds the default recovery middleware
	htmlFs, _ := fs.Sub(embeddedassets, "html")
	ws.AddFS(http.FS(htmlFs))

	// Add debug functions
	if ui.GetLoglevel() >= ui.LevelDebug {
		debugfuncs(ws)
	}
	return ws
}

func (ws *webservice) Init(r gin.IRoutes) {
	// Add stock functions
	ws.Initialized = true
	ws.AddUIEndpoints(r)
	ws.AddPreferencesEndpoints(r)
	ws.AddAnalysisEndpoints(r)
}

func (w *webservice) AddLocalHTML(path string) error {
	if !w.localhtmlused {
		// Clear embedded html filesystem
		w.UnionFS = UnionFS{}
		w.localhtmlused = true
	}
	// Override embedded HTML if asked to
	stat, err := os.Stat(path)
	if err == nil && stat.IsDir() {
		// Use local files if they exist
		ui.Info().Msgf("Adding local HTML folder %v", path)
		w.AddFS(http.FS(os.DirFS(path)))
		return nil
	}
	return fmt.Errorf("could not add local HTML folder %v, failure: %v", path, err)
}

func (ws *webservice) Analyze(path string) error {
	if ws.status != NoData && ws.status == Ready {
		return errors.New("Adalanche is not ready to load new data")
	}

	ws.status = Analyzing
	objs, err := engine.Run(path)
	ws.Objs = objs

	if err != nil {
		ws.status = Error
		return err
	}

	ws.status = PostAnalyzing
	engine.PostProcess(objs)

	ws.status = Ready

	return nil
}

func (ws *webservice) QuitChan() <-chan bool {
	return ws.quit
}

func (ws *webservice) Quit() {
	close(ws.quit)
}

func (ws *webservice) Start(bind string) error {
	if !ws.Initialized {
		ws.Init(ws.Router)
	}

	// Profiling
	pprof.Register(ws.Router)

	ws.srv = &http.Server{
		Addr:    bind,
		Handler: ws.Router,
	}

	ws.Router.GET("/", func(c *gin.Context) {
		indexfile, err := ws.UnionFS.Open("index.html")
		if err != nil {
			ui.Error().Msgf("Could not open index.html: %v", err)
		}
		rawindex, _ := io.ReadAll(indexfile)
		indextemplate := template.Must(template.New("index").Parse(string(rawindex)))

		err = indextemplate.Execute(c.Writer, struct {
			AdditionalHeaders []string
		}{
			AdditionalHeaders: ws.AdditionalHeaders,
		})
		if err != nil {
			ui.Error().Msgf("Could not render template index.html: %v", err)
		}
	})
	ws.Router.Use(static.Serve("/", ws.UnionFS))

	// w.Router.StaticFS("/", http.FS(w.UnionFS))

	go func() {
		if err := ws.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ui.Fatal().Msgf("Problem launching webservice listener: %s", err)
		}
	}()

	ui.Info().Msgf("Listening - navigate to http://%v/ ... (ctrl-c or similar to quit)", bind)

	return nil
}

func (ws *webservice) ServeTemplate(c *gin.Context, path string, data any) {
	templatefile, err := ws.UnionFS.Open(path)
	if err != nil {
		ui.Fatal().Msgf("Could not open template %v: %v", path, err)
	}
	rawtemplate, _ := io.ReadAll(templatefile)
	template, err := template.New(path).Parse(string(rawtemplate))
	if err != nil {
		c.AbortWithError(500, err)
		return
	}
	template.Execute(c.Writer, data)
}
