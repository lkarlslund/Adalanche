// Package mcpserver serves the Model Context Protocol at /mcp on the web
// service, so assistants and other tools can work with the loaded graph:
// find and inspect nodes, follow edges and why they exist, run queries and
// explain the routes between nodes. Secrets never leave it.
package mcpserver

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/frontend"
	"github.com/lkarlslund/adalanche/modules/version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func init() {
	frontend.AddOption(func(ws *frontend.WebService) error {
		s := newServer(webSource{ws})
		ws.Router.Any("/mcp", gin.WrapH(s.handler()))
		return nil
	})
}

// graphSource is what the server reads: the web service, or a fixed graph
// in tests.
type graphSource interface {
	Status() frontend.WebServiceStatus
	Graph() *engine.IndexedGraph
	// Docs is where the documentation is read from, or nil.
	Docs() DocsFS
}

type webSource struct{ ws *frontend.WebService }

func (w webSource) Status() frontend.WebServiceStatus { return w.ws.Status() }
func (w webSource) Graph() *engine.IndexedGraph       { return w.ws.SuperGraph }
func (w webSource) Docs() DocsFS                      { return w.ws.UnionFS }

// Server is the MCP server of one web service.
type Server struct {
	source graphSource
	mcp    *mcp.Server

	// The graph node ids were last given out for, and its load tag.
	loadLock  sync.Mutex
	loadGraph *engine.IndexedGraph
	load      string
}

var (
	extensionsLock sync.Mutex
	extensions     []func(*Server)
)

// AddTools registers a function that adds tools, such as an integration's,
// to every MCP server.
func AddTools(add func(*Server)) {
	extensionsLock.Lock()
	defer extensionsLock.Unlock()
	extensions = append(extensions, add)
}

func newServer(source graphSource) *Server {
	s := &Server{
		source: source,
		mcp: mcp.NewServer(&mcp.Implementation{
			Name:    "adalanche",
			Title:   "Adalanche",
			Version: version.ProgramVersionShort(),
		}, &mcp.ServerOptions{
			Instructions: instructions,
		}),
	}
	s.addNodeTools()
	s.addQueryTools()
	s.addRouteTools()
	s.addACLTools()
	s.addDocTools()
	s.addResources()
	extensionsLock.Lock()
	defer extensionsLock.Unlock()
	for _, add := range extensions {
		add(s)
	}
	return s
}

const instructions = `Adalanche holds a graph of directory and machine objects (users, groups, computers, machines, GPOs and more) and the edges between them. An edge from A to B means A can do something to B, such as reset its password or control it through group membership; edge types name what, and edges record why they exist. Start with get_status and list_schema, find nodes with find_nodes, and use explain_routes to show how one node can reach others. Queries use AQL: read its documentation with get_doc (name aql) before writing one, and list_saved_queries has ready-made ones; list_docs lists the rest of the documentation. Node ids (123@k3f9) hold only for one load of the graph, named by the tag after the @: they change whenever the graph loads again, and ids from an earlier load are refused. To refer to a node later, or across conversations, use its key (such as objectSid=S-1-5-...), which every node carries and which tools take as id. Passwords, hashes and keys are never returned.`

// handler serves MCP over streamable HTTP. Browsers on other sites cannot
// call it; the SDK also refuses requests addressed to other host names
// while the web service listens on localhost.
func (s *Server) handler() http.Handler {
	return http.NewCrossOriginProtection().Handler(mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s.mcp },
		&mcp.StreamableHTTPOptions{
			JSONResponse:   true,
			SessionTimeout: 30 * time.Minute,
			// A tool's context ends when its request does, which stops
			// long searches the client gave up on.
			PropagateRequestCancellation: true,
		}))
}

// MCP returns the underlying server, to add tools to.
func (s *Server) MCP() *mcp.Server {
	return s.mcp
}

var errNotReady = errors.New("adalanche has not finished loading data yet; check get_status")

// Graph returns the loaded graph, or an error while data is still loading.
func (s *Server) Graph() (*engine.IndexedGraph, error) {
	g := s.source.Graph()
	if s.source.Status() != frontend.Ready || g == nil {
		return nil, errNotReady
	}
	s.loadTag(g)
	return g, nil
}

// Meta is the status part of every tool result.
type Meta struct {
	Status string `json:"status"`
	Ready  bool   `json:"ready"`
	Load   string `json:"load,omitempty" jsonschema:"tag of this load of the graph; node ids carry it and change when it does"`
}

// Meta returns the status part of a tool result.
func (s *Server) Meta() Meta {
	status := s.source.Status()
	return Meta{Status: status.String(), Ready: status == frontend.Ready, Load: s.currentTag()}
}

// cancelled reports whether the client has given up on a tool call; long
// loops check it now and then.
func cancelled(ctx context.Context, step int) bool {
	return step%4096 == 0 && ctx.Err() != nil
}
