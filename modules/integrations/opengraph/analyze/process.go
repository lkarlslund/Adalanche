package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/opengraph"
)

// The source's node identifier, which edges reference with match_by "id".
// It is kept as an ordinary attribute; engine node IDs are process-local.
var attributeOpenGraphID = engine.NewAttribute("id")

func processOpenGraphData(g *engine.IndexedGraph, ogd opengraph.Model) error {
	// process nodes
	for _, node := range ogd.Graph.Nodes {
		data := make([]any, 0, len(node.Properties)*2+4)
		data = append(data, attributeOpenGraphID, node.ID)
		if len(node.Kinds) > 0 {
			data = append(data, engine.Type, node.Kinds[0])
		}
		for attrName, value := range node.Properties {
			attr := engine.NewAttribute(attrName)
			data = append(data, attr, value)
		}
		g.AddNew(data...)
	}

	// process edges
	seenMatchAttrs := make(map[engine.Attribute]struct{})
	for _, edge := range ogd.Graph.Edges {
		startAttr := engine.NewAttribute(edge.Start.MatchBy)
		endAttr := engine.NewAttribute(edge.End.MatchBy)

		startNode, startFound := g.FindOrAdd(startAttr, engine.NV(edge.Start.MatchBy))
		endNode, endFound := g.FindOrAdd(endAttr, engine.NV(edge.End.MatchBy))

		if _, seen := seenMatchAttrs[startAttr]; !seen && !startFound {
			startAttr.Flag(engine.Merge)
			seenMatchAttrs[startAttr] = struct{}{}
		}
		if _, seen := seenMatchAttrs[endAttr]; !seen && !endFound {
			endAttr.Flag(engine.Merge)
			seenMatchAttrs[endAttr] = struct{}{}
		}

		edge := engine.NewEdge(edge.Kind)
		g.EdgeTo(startNode, endNode, edge)
	}

	return nil
}
