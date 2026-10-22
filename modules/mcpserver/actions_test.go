package mcpserver

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/frontend"
)

// Tools are a few categories, each taking an action; the OSS ones only read.
func TestCategoryTools(t *testing.T) {
	g, _ := testGraph(t)
	session := connect(t, fixedSource{g, frontend.Ready})

	tools, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%v is not marked read-only", tool.Name)
		}
		body, _ := json.Marshal(tool.InputSchema)
		var schema struct {
			Properties map[string]struct {
				Enum []string `json:"enum"`
			} `json:"properties"`
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(body, &schema); err != nil {
			t.Fatal(err)
		}
		if len(schema.Properties["action"].Enum) == 0 || !slices.Contains(schema.Required, "action") {
			t.Errorf("%v: no required action enum in %s", tool.Name, body)
		}
	}
	slices.Sort(names)
	if want := []string{"aql", "docs", "graph", "nodes", "routes"}; !slices.Equal(names, want) {
		t.Errorf("tools %v, want %v", names, want)
	}
	for _, tool := range tools.Tools {
		if tool.Name == "nodes" && (!strings.Contains(tool.Description, "- find(") || !strings.Contains(tool.Description, "id*")) {
			t.Errorf("nodes description does not list the actions and their fields: %v", tool.Description)
		}
	}

	var out struct{}
	for _, c := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"nodes", map[string]any{}, "action must be one of find, details, neighbors, acl"},
		{"nodes", map[string]any{"action": "explode"}, "action must be one of"},
		{"nodes", map[string]any{"action": "find", "limit": "lots"}, "validating arguments for find"},
		{"nodes", map[string]any{"action": "details"}, "validating arguments for details"}, // id is required
	} {
		if msg := call(t, session, c.tool, c.args, &out); !strings.Contains(msg, c.want) {
			t.Errorf("%v %v: %q, want it to say %q", c.tool, c.args, msg, c.want)
		}
	}
}
