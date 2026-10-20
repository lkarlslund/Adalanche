package frontend

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
)

func TestNodeDetailsIdentity(t *testing.T) {
	node := engine.NewNode(engine.Name, "Sample user", engine.Type, engine.NodeTypeUser.ValueString(),
		engine.DistinguishedName, "CN=Sample,DC=example,DC=test")
	details := apiNodeDetails(node, true)
	if details.Type != "User" || details.IdentityField != "distinguishedName" || details.Identity != node.DN() {
		t.Fatalf("incorrect identity: %+v", details)
	}
	missing := apiNodeDetails(engine.NewNode(engine.Name, "Unidentified"), true)
	if missing.Identity != "" || missing.IdentityField != "" {
		t.Fatal("session identity presented as primary identity")
	}
}

func TestRawNodeDetailsAreUntruncated(t *testing.T) {
	ws := NewWebservice()
	ws.API = ws.Router.Group("/api")
	AddDataEndpoints(ws)
	ws.status = Ready
	ws.SuperGraph = engine.NewIndexedGraph()
	attribute := engine.NewAttribute("detailsTestLongValue")
	value := strings.Repeat("sample", 100)
	node := engine.NewNode(engine.Name, "Sample", attribute, value)
	enginetest.Add(ws.SuperGraph, node)
	for _, raw := range []bool{false, true} {
		url := fmt.Sprintf("/api/details/nodeid/%d", node.ID())
		if raw {
			url += "?format=raw"
		}
		recorder := httptest.NewRecorder()
		ws.engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, url, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d", recorder.Code)
		}
		var details APINodeDetails
		if err := json.Unmarshal(recorder.Body.Bytes(), &details); err != nil {
			t.Fatal(err)
		}
		got := details.Attributes[attribute.String()][0]
		if raw && (got != value || recorder.Header().Get("Cache-Control") != "no-store") {
			t.Fatal("raw values were truncated or cacheable")
		}
		if !raw && len(got) >= len(value) {
			t.Fatal("preview unexpectedly expanded the full value")
		}
	}
}

func TestAttributeEndpointServesOnlyImagesInline(t *testing.T) {
	ws := NewWebservice()
	ws.API = ws.Router.Group("/api")
	AddDataEndpoints(ws)
	ws.status = Ready
	ws.SuperGraph = engine.NewIndexedGraph()
	picture := engine.NewAttribute("attributeTestPicture")
	markup := engine.NewAttribute("attributeTestMarkup")
	png := "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
	node := engine.NewNode(engine.Name, "Sample", picture, png, markup, "<html><script>alert(1)</script></html>")
	enginetest.Add(ws.SuperGraph, node)

	if details := apiNodeDetails(node, true); len(details.Images) != 1 || details.Images[0] != picture.String() {
		t.Fatalf("images = %v", details.Images)
	}
	get := func(path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		ws.engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/attribute/nodeid/%d/%s", node.ID(), path), nil))
		return recorder
	}
	image := get(picture.String())
	if image.Code != http.StatusOK || image.Header().Get("Content-Type") != "image/png" || image.Body.String() != png ||
		image.Header().Get("Content-Disposition") != "" || image.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("image served as %d %v", image.Code, image.Header())
	}
	page := get(markup.String())
	if page.Code != http.StatusOK || page.Header().Get("Content-Type") != "application/octet-stream" ||
		page.Header().Get("Content-Disposition") != "attachment" || page.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("markup served as %d %v", page.Code, page.Header())
	}
	if missing := get(picture.String() + "?index=1"); missing.Code != http.StatusNotFound {
		t.Fatalf("missing value: %d", missing.Code)
	}
}
