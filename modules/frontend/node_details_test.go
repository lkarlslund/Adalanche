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
