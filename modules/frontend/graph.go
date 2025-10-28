package frontend

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/lkarlslund/adalanche/modules/graph"
)

type GraphLayoutRequest struct {
	Graph   RequestGraph            `json:"graph"`
	Layout  string                  `json:"layout"`
	Options graph.COSELayoutOptions `json:"options"`
}

type RequestGraph struct {
	Nodes []RequestNode `json:"nodes"`
	Edges []RequestEdge `json:"edges"`
}

type Position struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type RequestNode struct {
	Id       string         `json:"id"`
	Data     map[string]any `json:"data"`
	Height   float64        `json:"height,omitempty"`
	Width    float64        `json:"width,omitempty"`
	Position Position       `json:"position"`
}

type RequestEdge struct {
	Id   string `json:"id"`
	From string `json:"from"`
	To   string `json:"to"`
}

type DummyNode string
type DummyEdge struct{}

// Dummy function to satisfy interface
func (de DummyEdge) Merge(de2 DummyEdge) DummyEdge {
	return de
}

type ResponseNode struct {
	Id string  `json:"id"`
	X  float64 `json:"x"`
	Y  float64 `json:"y"`
}

type GraphLayoutResponse []ResponseNode

func AddGraphEndpoints(ws *WebService) {
	// Placeholder for adding graph-related endpoints
	ws.API.POST("/graph/layout", func(c *gin.Context) {
		// build incominggraph object from JSON post body
		req := GraphLayoutRequest{
			Options: graph.DefaultLayoutSettings(),
		}
		err := c.ShouldBindBodyWith(&req, binding.JSON)

		if err != nil {
			c.String(500, err.Error())
			return
		}

		// Build a graph using this
		g := graph.NewGraph[DummyNode, DummyEdge]()
		for _, n := range req.Graph.Nodes {
			g.AddNode(DummyNode(n.Id))
		}
		for _, e := range req.Graph.Edges {
			g.AddEdge(DummyNode(e.From), DummyNode(e.To), DummyEdge{})
		}

		var coordinates map[DummyNode][2]float64
		switch req.Layout {
		case "cosev2":
			// Use COSE v2 layout
			coordinates = g.COSELayoutV2(req.Options)
		default:
			coordinates = g.COSELayoutV1(req.Options)
		}

		// Build response
		respNodes := make([]ResponseNode, 0, len(req.Graph.Nodes))
		for id, coord := range coordinates {
			respNodes = append(respNodes, ResponseNode{
				Id: string(id),
				X:  coord[0],
				Y:  coord[1],
			})
		}

		c.JSON(200, respNodes)
	})
}
