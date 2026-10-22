package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lkarlslund/adalanche/modules/frontend"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A client keeps working when adalanche restarts behind the same address:
// the new process has no sessions, and is not asked for one.
func TestClientSurvivesRestart(t *testing.T) {
	var current atomic.Pointer[http.Handler]
	start := func() {
		g, _ := testGraph(t)
		handler := newServer(fixedSource{g, frontend.Ready}).handler()
		current.Store(&handler)
	}
	start()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*current.Load()).ServeHTTP(w, r)
	}))
	t.Cleanup(web.Close)

	session, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).
		Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: web.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })

	var before, after statusOutput
	if msg := call(t, session, "graph status", nil, &before); msg != "" || !before.Meta.Ready {
		t.Fatalf("before restart: %+v %s", before, msg)
	}
	start()
	if msg := call(t, session, "graph status", nil, &after); msg != "" || !after.Meta.Ready {
		t.Fatalf("after restart: %+v %s", after, msg)
	}
	if before.Meta.Load == after.Meta.Load {
		t.Error("the restarted server should be on a new load of the graph")
	}
}

// A request carrying a session id from before a restart is answered, not
// refused as an unknown session.
func TestStaleSessionIDAccepted(t *testing.T) {
	g, _ := testGraph(t)
	handler := newServer(fixedSource{g, frontend.Ready}).handler()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"graph","arguments":{"action":"status"}}}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Mcp-Session-Id", "from-before-the-restart")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"ready":true`) {
		t.Fatalf("got %d: %s", recorder.Code, recorder.Body.String())
	}
}
