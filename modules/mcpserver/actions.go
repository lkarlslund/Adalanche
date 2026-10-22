package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tools are grouped by category, each tool taking an action argument, so a
// client sees a handful of tools instead of one per operation. Each action
// keeps its own typed handler and input schema: the arguments are checked
// against the action's schema before it runs, so a wrong or missing field
// gets the same precise error a tool of its own would give.
//
// MCP marks a tool as reading or writing, not an action, so a category holds
// either only actions that read or only actions that write.

// Action is one operation of a category tool.
type Action struct {
	Name        string
	Description string
	schema      *jsonschema.Schema
	resolved    *jsonschema.Resolved
	run         func(ctx context.Context, req *mcp.CallToolRequest, args json.RawMessage) (*mcp.CallToolResult, any, error)
}

// NewAction makes an action of a typed handler, as mcp.AddTool takes one.
func NewAction[In, Out any](name, description string, h mcp.ToolHandlerFor[In, Out]) Action {
	schema, err := jsonschema.For[In](&jsonschema.ForOptions{})
	if err != nil {
		panic(fmt.Errorf("action %v: input schema: %w", name, err))
	}
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
	if err != nil {
		panic(fmt.Errorf("action %v: input schema: %w", name, err))
	}
	return Action{
		Name:        name,
		Description: description,
		schema:      schema,
		resolved:    resolved,
		run: func(ctx context.Context, req *mcp.CallToolRequest, args json.RawMessage) (*mcp.CallToolResult, any, error) {
			var in In
			if err := json.Unmarshal(args, &in); err != nil {
				return nil, nil, err
			}
			res, out, err := h(ctx, req, in)
			return res, out, err
		},
	}
}

// Category is a tool grouping actions.
type Category struct {
	Name        string
	Title       string
	Description string
	// Writes marks a category whose actions change something; otherwise
	// every action only reads and clients may run them without asking.
	Writes      bool
	Destructive bool // with Writes: an action can remove what users made
	Actions     []Action
}

// AddCategory adds a category tool. Categories are how integrations add
// tools too (see AddTools).
func (s *Server) AddCategory(c Category) {
	byName := map[string]Action{}
	var names, lines []string
	for _, a := range c.Actions {
		if _, taken := byName[a.Name]; taken {
			panic(fmt.Errorf("category %v: action %v twice", c.Name, a.Name))
		}
		byName[a.Name] = a
		names = append(names, a.Name)
		lines = append(lines, "- "+a.Name+fieldList(a.schema)+": "+a.Description)
	}
	annotations := &mcp.ToolAnnotations{Title: c.Title, ReadOnlyHint: !c.Writes, OpenWorldHint: boolPointer(false)}
	if c.Writes {
		annotations.DestructiveHint = boolPointer(c.Destructive)
		annotations.IdempotentHint = true
	}
	s.mcp.AddTool(&mcp.Tool{
		Name:        c.Name,
		Title:       c.Title,
		Description: c.Description + " Pass action, and the fields that action takes (* marks required ones):\n" + strings.Join(lines, "\n"),
		InputSchema: mergedSchema(c.Name, names, c.Actions),
		Annotations: annotations,
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fail := func(err error) (*mcp.CallToolResult, error) {
			var res mcp.CallToolResult
			res.SetError(err)
			return &res, nil
		}
		args := map[string]any{}
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
				return fail(fmt.Errorf("unmarshaling arguments: %w", err))
			}
		}
		name, _ := args["action"].(string)
		action, found := byName[name]
		if !found {
			return fail(fmt.Errorf("action must be one of %v", strings.Join(names, ", ")))
		}
		delete(args, "action")
		if err := action.resolved.ApplyDefaults(&args); err != nil {
			return fail(fmt.Errorf("%v: %w", name, err))
		}
		if err := action.resolved.Validate(args); err != nil {
			return fail(fmt.Errorf("validating arguments for %v: %w", name, err))
		}
		raw, err := json.Marshal(args)
		if err != nil {
			return fail(err)
		}
		res, out, err := action.run(ctx, req, raw)
		if err != nil {
			if wire, ok := err.(*jsonrpc.Error); ok {
				return nil, wire
			}
			return fail(err)
		}
		if res == nil {
			res = &mcp.CallToolResult{}
		}
		if out != nil {
			body, err := json.Marshal(out)
			if err != nil {
				return nil, fmt.Errorf("marshaling output: %w", err)
			}
			res.StructuredContent = json.RawMessage(body)
			if res.Content == nil {
				res.Content = []mcp.Content{&mcp.TextContent{Text: string(body)}}
			}
		}
		return res, nil
	})
}

func boolPointer(b bool) *bool { return &b }

// fieldList names an action's fields, marking the required ones.
func fieldList(schema *jsonschema.Schema) string {
	var fields []string
	for _, name := range slices.Sorted(maps.Keys(schema.Properties)) {
		if slices.Contains(schema.Required, name) {
			name += "*"
		}
		fields = append(fields, name)
	}
	return "(" + strings.Join(fields, ", ") + ")"
}

// mergedSchema is the category tool's input: action, and every field any
// action takes. A field several actions take must mean the same type; its
// description says which actions take it.
func mergedSchema(category string, names []string, actions []Action) *jsonschema.Schema {
	type use struct {
		action string
		schema *jsonschema.Schema
	}
	uses := map[string][]use{}
	for _, a := range actions {
		for name, p := range a.schema.Properties {
			uses[name] = append(uses[name], use{a.Name, p})
		}
	}
	merged := &jsonschema.Schema{
		Type:       "object",
		Properties: map[string]*jsonschema.Schema{},
		Required:   []string{"action"},
	}
	for name, us := range uses {
		if name == "action" {
			panic(fmt.Errorf("category %v: an action takes a field named action", category))
		}
		first := us[0].schema
		var describe []string
		same := true
		for _, u := range us {
			if u.schema.Type != first.Type || !slices.Equal(u.schema.Types, first.Types) {
				panic(fmt.Errorf("category %v: field %v has different types in %v and %v", category, name, us[0].action, u.action))
			}
			same = same && u.schema.Description == first.Description
			if u.schema.Description != "" {
				describe = append(describe, u.action+": "+u.schema.Description)
			}
		}
		p := *first
		var actionNames []string
		for _, u := range us {
			actionNames = append(actionNames, u.action)
		}
		switch {
		case same:
			p.Description = "(" + strings.Join(actionNames, ", ") + ") " + first.Description
		default:
			p.Description = strings.Join(describe, "; ")
		}
		merged.Properties[name] = &p
	}
	merged.Properties["action"] = &jsonschema.Schema{
		Type:        "string",
		Enum:        toAny(names),
		Description: "what to do: " + strings.Join(names, ", "),
	}
	return merged
}

func toAny(names []string) []any {
	out := make([]any, len(names))
	for i, n := range names {
		out[i] = n
	}
	return out
}
