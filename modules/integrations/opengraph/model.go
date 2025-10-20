package opengraph

const Suffix = ".opengraph.json"

//go:tool generate go run github.com/bytedance/sonic/cmd/sonic -type OpenGraphData -out model_sonic_gen.go
type Model struct {
	Metadata map[string]string `json:"metadata"` // for source_kind data
	Graph    OpenGraph         `json:"graph"`
}

type OpenGraph struct {
	Nodes []OpenGraphNode `json:"nodes"`
	Edges []OpenGraphEdge `json:"edges"`
}

type OpenGraphNode struct {
	ID         string         `json:"id"`
	Kinds      []string       `json:"kinds"` // translates to Type in our model
	Properties map[string]any `json:"properties,omitempty"`
}

type OpenGraphEdge struct {
	Start OpenNodeReference `json:"start"`
	End   OpenNodeReference `json:"end"`
	Kind  string            `json:"kind"` // translates to EdgeType in our model
}

type OpenNodeReference struct {
	MatchBy    string         `json:"match_by"`
	Value      any            `json:"value"`
	Kind       string         `json:"kind,omitempty"`
	Properties map[string]any `json:"properties,omitempty"` // not supported yet
}
