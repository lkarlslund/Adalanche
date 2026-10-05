package frontend

import (
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestShouldCompress(t *testing.T) {
	server := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8080}
	for _, tt := range []struct {
		name, remote, path, encoding, connection string
		want                                     bool
	}{
		{"remote client", "198.51.100.7:50000", "/api/aql/analyze", "gzip, br", "", true},
		{"loopback client", "127.0.0.1:50000", "/api/aql/analyze", "gzip", "", false},
		{"IPv6 loopback client", "[::1]:50000", "/api/aql/analyze", "gzip", "", false},
		{"client on the server's own address", "192.0.2.10:50000", "/api/aql/analyze", "gzip", "", false},
		{"no gzip accepted", "198.51.100.7:50000", "/api/aql/analyze", "br", "", false},
		{"connection upgrade", "198.51.100.7:50000", "/api/backend/ws-progress", "gzip", "Upgrade", false},
		{"compressed file", "198.51.100.7:50000", "/icons/node.png", "gzip", "", false},
	} {
		request := httptest.NewRequest(http.MethodGet, tt.path, nil)
		request.RemoteAddr = tt.remote
		request.Header.Set("Accept-Encoding", tt.encoding)
		if tt.connection != "" {
			request.Header.Set("Connection", tt.connection)
		}
		request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, net.Addr(server)))
		if got := shouldCompress(&gin.Context{Request: request}); got != tt.want {
			t.Errorf("%s: compress %v, want %v", tt.name, got, tt.want)
		}
	}
}

// Responses reach remote and local clients exactly as handlers wrote them,
// compressed or not, and a handler that writes nothing still gets the
// API's status reply.
func TestResponsesThroughCompression(t *testing.T) {
	ws := NewWebservice()
	small := `{"adalanche":"` + strings.Repeat("s", 700) + `"}`
	large := `{"adalanche":"` + strings.Repeat("l", 7000) + `"}`
	ws.API.GET("/small", func(c *gin.Context) { c.Data(200, "application/json", []byte(small)) })
	ws.API.GET("/large", func(c *gin.Context) { c.Data(200, "application/json", []byte(large)) })
	ws.API.GET("/nothing", func(c *gin.Context) {})
	for _, remote := range []string{"198.51.100.7:50000", "127.0.0.1:50000"} {
		for path, want := range map[string]string{"/api/small": small, "/api/large": large, "/api/nothing": `{"status":"ok"}`} {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.RemoteAddr = remote
			request.Header.Set("Accept-Encoding", "gzip")
			recorder := httptest.NewRecorder()
			ws.engine.ServeHTTP(recorder, request)
			response := recorder.Result()
			body := io.Reader(response.Body)
			if response.Header.Get("Content-Encoding") == "gzip" {
				reader, err := gzip.NewReader(body)
				if err != nil {
					t.Fatalf("%s from %s: %v", path, remote, err)
				}
				body = reader
			}
			got, err := io.ReadAll(body)
			if err != nil {
				t.Fatalf("%s from %s: %v", path, remote, err)
			}
			if string(got) != want {
				t.Errorf("%s from %s: got %d bytes %.40q..., want %d bytes", path, remote, len(got), got, len(want))
			}
		}
	}
}
