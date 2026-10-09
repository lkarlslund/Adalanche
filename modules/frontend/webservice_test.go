package frontend

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewWebserviceSetsIsolationHeaders(t *testing.T) {
	t.Parallel()

	ws := NewWebservice()
	ws.Router.GET("/test-headers", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/test-headers", nil)

	ws.engine.ServeHTTP(recorder, request)

	if got := recorder.Header().Get("Cross-Origin-Opener-Policy"); got != "same-origin" {
		t.Fatalf("unexpected COOP header %q", got)
	}
	if got := recorder.Header().Get("Cross-Origin-Embedder-Policy"); got != "require-corp" {
		t.Fatalf("unexpected COEP header %q", got)
	}
	if got := recorder.Header().Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
		t.Fatalf("unexpected CORP header %q", got)
	}
}
