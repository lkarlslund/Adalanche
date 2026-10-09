package mcpserver

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DocsFS is where the documentation the web interface shows is read from:
// markdown files in docs/.
type DocsFS interface {
	Open(name string) (fs.File, error)
	OpenDir(name string) ([]fs.DirEntry, error)
}

const docsDir = "docs"

func (s *Server) addDocTools() {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "list_docs",
		Description: "List Adalanche's documentation: each document's name, title and section headings. Read aql before writing queries.",
	}, s.listDocs)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "get_doc",
		Description: "Read a document from Adalanche's documentation as markdown, whole or one section. aql describes the query language.",
	}, s.getDoc)

	docs := s.source.Docs()
	if docs == nil {
		return
	}
	for _, name := range docNames(docs) {
		text, err := readDoc(docs, name)
		if err != nil {
			continue
		}
		title, _ := docOutline(text)
		uri := "adalanche://docs/" + name
		s.mcp.AddResource(&mcp.Resource{URI: uri, Name: "doc-" + name, Title: title, Description: "Documentation: " + title, MIMEType: "text/markdown"},
			func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				text, err := readDoc(docs, name)
				if err != nil {
					return nil, err
				}
				return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "text/markdown", Text: text}}}, nil
			})
	}
}

// DocInfo describes one document.
type DocInfo struct {
	Name     string   `json:"name" jsonschema:"the name to pass to get_doc"`
	Title    string   `json:"title"`
	Sections []string `json:"sections,omitempty" jsonschema:"section headings, to pass to get_doc as section"`
}

type listDocsOutput struct {
	Docs []DocInfo `json:"docs"`
}

func (s *Server) listDocs(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, listDocsOutput, error) {
	docs := s.source.Docs()
	if docs == nil {
		return nil, listDocsOutput{}, fmt.Errorf("no documentation is available")
	}
	var out listDocsOutput
	for _, name := range docNames(docs) {
		text, err := readDoc(docs, name)
		if err != nil {
			continue
		}
		title, sections := docOutline(text)
		out.Docs = append(out.Docs, DocInfo{Name: name, Title: title, Sections: sections})
	}
	return nil, out, nil
}

type getDocInput struct {
	Name    string `json:"name" jsonschema:"the document, such as aql, as list_docs names it"`
	Section string `json:"section,omitempty" jsonschema:"only this section, by its heading; the whole document when left out"`
}

type getDocOutput struct {
	Name     string `json:"name"`
	Markdown string `json:"markdown"`
}

func (s *Server) getDoc(_ context.Context, _ *mcp.CallToolRequest, in getDocInput) (*mcp.CallToolResult, getDocOutput, error) {
	docs := s.source.Docs()
	if docs == nil {
		return nil, getDocOutput{}, fmt.Errorf("no documentation is available")
	}
	name := strings.TrimSuffix(path.Base(strings.TrimSpace(in.Name)), ".md")
	text, err := readDoc(docs, name)
	if err != nil {
		return nil, getDocOutput{}, fmt.Errorf("no document %q; list_docs lists them", in.Name)
	}
	if in.Section != "" {
		section, found := docSection(text, in.Section)
		if !found {
			_, sections := docOutline(text)
			return nil, getDocOutput{}, fmt.Errorf("%s has no section %q; it has: %s", name, in.Section, strings.Join(sections, "; "))
		}
		text = section
	}
	return nil, getDocOutput{Name: name, Markdown: text}, nil
}

// docNames lists the documents, index first.
func docNames(docs DocsFS) []string {
	entries, err := docs.OpenDir(docsDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") {
			names = append(names, strings.TrimSuffix(entry.Name(), ".md"))
		}
	}
	slices.SortFunc(names, func(a, b string) int {
		switch {
		case a == b:
			return 0
		case a == "index":
			return -1
		case b == "index":
			return 1
		}
		return strings.Compare(a, b)
	})
	return names
}

func readDoc(docs DocsFS, name string) (string, error) {
	f, err := docs.Open(docsDir + "/" + name + ".md")
	if err != nil {
		return "", err
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	return string(body), err
}

// heading returns the level and text of a markdown heading line, or 0.
func heading(line string) (int, string) {
	level := 0
	for level < len(line) && line[level] == '#' {
		level++
	}
	if level == 0 || level > 6 || level >= len(line) || line[level] != ' ' {
		return 0, ""
	}
	return level, strings.TrimSpace(strings.TrimRight(line[level:], "# "))
}

// docLines calls fn for each line with its heading level and text, leaving
// out lines in fenced code blocks, where # starts comments.
func docLines(text string, fn func(line string, level int, title string) bool) {
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	fenced := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
		}
		level, title := 0, ""
		if !fenced {
			level, title = heading(line)
		}
		if !fn(line, level, title) {
			return
		}
	}
}

// docOutline returns a document's title, its first heading, and every
// heading as a section.
func docOutline(text string) (string, []string) {
	var title string
	var sections []string
	docLines(text, func(_ string, level int, heading string) bool {
		if level == 0 {
			return true
		}
		if title == "" {
			title = heading
		}
		sections = append(sections, heading)
		return true
	})
	return title, sections
}

// docSection returns the section under a heading, up to the next heading of
// the same or a higher level.
func docSection(text, want string) (string, bool) {
	var b strings.Builder
	inside, level := false, 0
	docLines(text, func(line string, l int, title string) bool {
		if inside && l > 0 && l <= level {
			return false
		}
		if !inside && l > 0 && strings.EqualFold(title, strings.TrimSpace(want)) {
			inside, level = true, l
		}
		if inside {
			b.WriteString(line)
			b.WriteByte('\n')
		}
		return true
	})
	return b.String(), inside
}
