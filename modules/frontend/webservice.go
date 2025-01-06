package frontend

import (
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
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
		if c.Writer.Status() >= 400 {
			logger = ui.Warn()
		}
		logger.Msgf("%s %s (%v) %v, %v bytes", c.Request.Method, path, c.Writer.Status(), time.Since(start), c.Writer.Size())
	})
	ws.engine.Use(gin.Recovery()) // adds the default recovery middleware
	ws.Router = ws.engine.Group("")
	ws.API = ws.Router.Group("/api")
	// Error handling
	ws.API.Use(func(ctx *gin.Context) {
		ctx.Next()

		ctx.Header(`Cache-Control`, `no-cache, no-store, no-transform, must-revalidate, private, max-age=0`)
		ctx.Header(`Pragma`, `no-cache`)

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

// Init initializes the web service by adding stock functions and setting up routes.
func (ws *WebService) Init(r gin.IRoutes) {
	// Add stock functions
	ws.Initialized = true
	AddUIEndpoints(ws)
	AddPreferencesEndpoints(ws)
	AddDataEndpoints(ws)
}

// Analyze analyzes paths for some purpose, though its implementation is missing in the provided code.
func (ws *WebService) Analyze(paths ...string) error {
	if ws.status != NoData && ws.status != Ready {
		return errors.New("Adalanche is already busy loading data")
	}

	ws.status = Analyzing

	var err error
	ws.Objs, err = engine.Run(paths...)
	if err != nil {
		ws.status = Error
		return err
	}
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

	ws.engine.Use(func(ctx *gin.Context) {
		file := ctx.Request.URL.Path
		if file == "/" {
			contents, err := ws.UnionFS.Open("index.html")
			if err != nil {
				ui.Error().Msgf("Could not open index.html: %v", err)
				ctx.Error(err)
				return
			}
			serveTemplate(contents, ctx, struct {
				AdditionalHeaders []string
			}{
				AdditionalHeaders: ws.AdditionalHeaders,
			})
			return
		}

		if !ws.UnionFS.Exists("", file) {
			ctx.AbortWithStatus(404)
			return
		}

		f, err := ws.UnionFS.Open(file)
		if err == nil {
			stat, err := f.Stat()
			if err != nil {
				ui.Error().Msgf("Problem doing stat on file %v in embedded fs: %v", file, err)
				ctx.AbortWithStatus(500)
				return
			}

			if stat.IsDir() {
				ctx.AbortWithStatus(403)
				return
			}

			switch strings.ToLower(filepath.Ext(file)) {
			case ".md":
				serveMarkDown(f, ctx)
			case ".tmpl":
				serveTemplate(f, ctx, nil)
			default:
				// derive content type from extension
				ct := mime.TypeByExtension(filepath.Ext(file))
				if ct == "" {
					// if no content type could be derived, try to detect it from the file's contents
					c, _ := io.ReadAll(io.LimitReader(f, 512)) // read up to 512 bytes for detection
					f.Seek(0, 0)                               // reset file pointer after detection
					ct = http.DetectContentType(c)
				}
				ctx.DataFromReader(200, stat.Size(), ct, f, nil)
			}
		}
	})

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

func serveMarkDown(r io.Reader, ctx *gin.Context) {
	md, _ := io.ReadAll(r)

	extensions := parser.CommonExtensions | parser.AutoHeadingIDs | parser.NoEmptyLineBeforeBlock
	p := parser.NewWithExtensions(extensions)
	doc := p.Parse(md)

	// create HTML renderer with extensions
	htmlFlags := html.CommonFlags | html.HrefTargetBlank
	opts := html.RendererOptions{Flags: htmlFlags}
	renderer := html.NewRenderer(opts)

	ctx.Status(200)
	ctx.Writer.Write(markdown.Render(doc, renderer))
}

func serveTemplate(r io.Reader, ctx *gin.Context, data any) {
	rawindex, _ := io.ReadAll(r)
	template, err := template.New("template").Parse(string(rawindex))
	if err != nil {
		ui.Error().Msgf("Error parsing template: %v", err)
		ctx.AbortWithError(500, err)
		return
	}
	ctx.Status(200)
	err = template.Execute(ctx.Writer, data)
	if err != nil {
		ui.Error().Msgf("Could not render template: %v", err)
		ctx.AbortWithError(500, err)
		return
	}
}
