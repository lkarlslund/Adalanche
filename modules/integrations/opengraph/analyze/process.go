package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/opengraph"
)

func processOpenGraphData(g *engine.IndexedGraph, ogd opengraph.Model) error {
	// process nodes
	for _, node := range ogd.Graph.Nodes {
		data := make([]any, 0, len(node.Properties)*2+4)
		data = append(data, engine.AttributeNodeId, node.ID)
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
		if _, seen := seenMatchAttrs[startAttr]; !seen {
			startAttr.Flag(engine.Merge)
			seenMatchAttrs[startAttr] = struct{}{}
		}
		endAttr := engine.NewAttribute(edge.End.MatchBy).Flag(engine.Merge)
		if _, seen := seenMatchAttrs[endAttr]; !seen {
			endAttr.Flag(engine.Merge)
			seenMatchAttrs[endAttr] = struct{}{}
		}

		startNode, _ := g.FindOrAdd(startAttr, engine.NV(edge.Start.MatchBy))
		endNode, _ := g.FindOrAdd(endAttr, engine.NV(edge.End.MatchBy))

		edge := engine.NewEdge(edge.Kind)
		g.EdgeTo(startNode, endNode, edge)
	}

	return nil
}
