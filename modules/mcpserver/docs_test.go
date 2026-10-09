package mcpserver

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/lkarlslund/adalanche/modules/frontend"
)

type mapDocs struct{ fstest.MapFS }

func (m mapDocs) OpenDir(name string) ([]fs.DirEntry, error) { return m.ReadDir(name) }

type docsSource struct {
	fixedSource
	docs DocsFS
}

func (d docsSource) Docs() DocsFS { return d.docs }

const aqlDoc = "# Adalanche Query Language\n\nIntro.\n\n## Syntax\n\nStart with REACH.\n\n```\n# not a heading\n```\n\n### Edges\n\nUse [].\n\n## Examples\n\nREACH start:(tag=hvt)\n"

func TestDocs(t *testing.T) {
	g, _ := testGraph(t)
	docs := mapDocs{fstest.MapFS{
		"docs/aql.md":   {Data: []byte(aqlDoc)},
		"docs/index.md": {Data: []byte("# Overview\n")},
		"docs/images/x": {Data: []byte("png")},
	}}
	session := connect(t, docsSource{fixedSource{g, frontend.Ready}, docs})

	var list listDocsOutput
	if msg := call(t, session, "list_docs", nil, &list); msg != "" {
		t.Fatal(msg)
	}
	if len(list.Docs) != 2 || list.Docs[0].Name != "index" || list.Docs[1].Name != "aql" {
		t.Fatalf("docs: %+v", list.Docs)
	}
	if aql := list.Docs[1]; aql.Title != "Adalanche Query Language" || strings.Join(aql.Sections, "|") != "Adalanche Query Language|Syntax|Edges|Examples" {
		t.Errorf("aql outline: %+v", aql)
	}

	var doc getDocOutput
	if msg := call(t, session, "get_doc", map[string]any{"name": "aql.md"}, &doc); msg != "" || doc.Markdown != aqlDoc {
		t.Errorf("whole doc: %s %q", msg, doc.Markdown)
	}
	if msg := call(t, session, "get_doc", map[string]any{"name": "aql", "section": "syntax"}, &doc); msg != "" {
		t.Fatal(msg)
	}
	if !strings.HasPrefix(doc.Markdown, "## Syntax") || !strings.Contains(doc.Markdown, "### Edges") || strings.Contains(doc.Markdown, "Examples") {
		t.Errorf("section: %q", doc.Markdown)
	}
	if msg := call(t, session, "get_doc", map[string]any{"name": "aql", "section": "nope"}, &doc); !strings.Contains(msg, "Syntax") {
		t.Errorf("missing section: %q", msg)
	}
	if msg := call(t, session, "get_doc", map[string]any{"name": "../../etc/passwd"}, &doc); !strings.Contains(msg, "no document") {
		t.Errorf("path outside docs: %q", msg)
	}

	resources, err := session.ListResources(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range resources.Resources {
		found = found || (r.URI == "adalanche://docs/aql" && r.MIMEType == "text/markdown")
	}
	if !found {
		t.Error("no aql resource")
	}
}
