package frontend

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	jsoniter "github.com/json-iterator/go"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/util"
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
type optionsetter func(ws *WebService) error
type WebService struct {
	quit     chan bool
	engine   *gin.Engine
	Router   *gin.RouterGroup
	API      *gin.RouterGroup
	Objs     *engine.Objects
	protocol string
	UnionFS
	// srv *http.Server
	AdditionalHeaders []string // Additional things to add to the main page
	srv               http.Server
	status            WebServiceStatus
	Initialized       bool
	localhtmlused     bool
}

var globaloptions []optionsetter
var optionsmutex sync.Mutex

func AddOption(os optionsetter) {
	optionsmutex.Lock()
	globaloptions = append(globaloptions, os)
	optionsmutex.Unlock()
}

func NewWebservice() *WebService {
	gin.SetMode(gin.ReleaseMode) // Has to happen first
	ws := &WebService{
		quit:     make(chan bool),
		engine:   gin.New(),
		protocol: "http",
	}
	ws.engine.Use(func(c *gin.Context) {
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
	ws.engine.Use(gin.Recovery()) // adds the default recovery middleware
	ws.Router = ws.engine.Group("")
	ws.API = ws.Router.Group("/api")
	// Error handling
	ws.API.Use(func(ctx *gin.Context) {
		ctx.Next()
		if !ctx.Writer.Written() {
			if ctx.IsAborted() {
				if ctx.Request.Response.StatusCode == 0 {
					// do something
				}
				if len(ctx.Errors) > 0 {
					status := gin.H{
						"status": "error",
						"error":  ctx.Errors.Last().Err.Error(),
						// "status": strconv.Itoa(ctx.Request.Response.StatusCode),
						// "detail":
					}
					statusj, _ := json.Marshal(status)
					ctx.Writer.Write(statusj)
				}
			} else {
				statusj, _ := json.Marshal(gin.H{"status": "ok"})
				ctx.Writer.Write(statusj)
			}
		} else {

		}
	})
	htmlFs, _ := fs.Sub(embeddedassets, "html")
	ws.AddFS(http.FS(htmlFs))
	// Add debug functions
	if ui.GetLoglevel() >= ui.LevelDebug {
		debugfuncs(ws)
	}
	// Change settings
	for _, os := range globaloptions {
		err := os(ws)
		if err != nil {
			ui.Error().Msgf("Error setting frontend option: %v", err)
		}
	}
	return ws
}
func (ws *WebService) RequireData(minimumStatus WebServiceStatus) func(ctx *gin.Context) {
	return func(ctx *gin.Context) {
		if ws.status < minimumStatus {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "no data"})
		}
	}
}
func WithCert(certfile, keyfile string) optionsetter {
	return func(ws *WebService) error {
		// create certificate from pem strings directly
		var cert tls.Certificate
		var err error
		if util.PathExists(certfile) && util.PathExists(keyfile) {
			cert, err = tls.LoadX509KeyPair(certfile, keyfile)
		} else {
			cert, err = tls.X509KeyPair([]byte(certfile), []byte(keyfile))
		}
		if err != nil {
			return err
		}
		ws.protocol = "https"
		ws.srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		ui.Info().Msgf("Certificate loaded and configured for DNS names %v", strings.Join(ws.srv.TLSConfig.Certificates[0].Leaf.DNSNames, ", "))
		return nil
	}
}
func WithLocalHTML(path string) optionsetter {
	return func(ws *WebService) error {
		if !ws.localhtmlused {
			// Clear embedded html filesystem
			ws.UnionFS = UnionFS{}
			ws.localhtmlused = true
		}
		// Override embedded HTML if asked to
		stat, err := os.Stat(path)
		if err == nil && stat.IsDir() {
			// Use local files if they exist
			ui.Info().Msgf("Adding local HTML folder %v", path)
			ws.AddFS(http.FS(os.DirFS(path)))
			return nil
		}
		return fmt.Errorf("could not add local HTML folder %v, failure: %v", path, err)
	}
}
func (ws *WebService) Init(r gin.IRoutes) {
	// Add stock functions
	ws.Initialized = true
	AddUIEndpoints(ws)
	AddPreferencesEndpoints(ws)
	AddDataEndpoints(ws)
}
func (ws *WebService) Analyze(paths ...string) error {
	if ws.status != NoData && ws.status != Ready {
		return errors.New("Adalanche is already busy loading data")
	}
	ws.status = Analyzing
	objs, err := engine.Run(paths...)
	if err != nil {
		ws.status = Error
		return err
	}
	ws.Objs = objs
	ws.status = PostAnalyzing
	engine.PostProcess(objs)
	ws.status = Ready
	return nil
}
func (ws *WebService) QuitChan() <-chan bool {
	return ws.quit
}
func (ws *WebService) Quit() {
	close(ws.quit)
}
func (ws *WebService) Start(bind string) error {
	if !ws.Initialized {
		ws.Init(ws.Router)
	}
	ws.srv.Addr = bind
	ws.srv.Handler = ws.engine
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
	ws.engine.Use(static.Serve("", ws.UnionFS))
	// bind to port and start listening for requests
	conn, err := net.Listen("tcp", ws.srv.Addr)
	if err != nil {
		return err
	}
	switch ws.protocol {
	case "http":
		go func() {
			if err := ws.srv.Serve(conn); err != nil && err != http.ErrServerClosed {
				ui.Fatal().Msgf("Problem launching webservice listener: %s", err)
			}
		}()
	case "https":
		go func() {
			if err := ws.srv.ServeTLS(conn, "", ""); err != nil && err != http.ErrServerClosed {
				ui.Fatal().Msgf("Problem launching webservice listener: %s", err)
			}
		}()
	}
	ui.Info().Msgf("Adalanche Web Service listening at %v://%v/ ... (ctrl-c or similar to quit)", ws.protocol, bind)
	return nil
}
func (ws *WebService) ServeTemplate(c *gin.Context, path string, data any) {
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
func WithProfiling() func(*WebService) {
	return func(ws *WebService) {
		// Profiling
		pprof.Register(ws.Router)
	}
}
