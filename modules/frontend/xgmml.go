package frontend

import (
	"encoding/xml"

	"github.com/lkarlslund/adalanche/modules/engine"
)

//	type XGMML struct {
//		XMLNAme xml.Name `xml:"graph"`
//		Graph   XGMMLGraph
//	}
func NewXGMMLGraph() XGMMLGraph {
	return XGMMLGraph{
		XMLNS:      "http://www.cs.rpi.edu/XGMML",
		XMLNSDC:    "http://purl.org/dc/elements/1.1/",
		XMLNSXLINK: "http://www.w3.org/1999/xlink",
		XMLNSRDF:   "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
		XMLNSCY:    "http://www.cytoscape.org",
		Directed:   1,
	}
}

type XGMMLGraph struct {
	XMLName    xml.Name `xml:"graph"`
	XMLNS      string   `xml:"xmlns,attr"`
	XMLNSDC    string   `xml:"xmlns:dc,attr"`
	XMLNSXLINK string   `xml:"xmlns:xlink,attr"`
	XMLNSRDF   string   `xml:"xmlns:rdf,attr"`
	XMLNSCY    string   `xml:"xmlns:cy,attr"`
	Label      string   `xml:"label,attr,omitempty"`
	Nodes      []XGMMLNode
	Edges      []XGMMLEdge
	Directed   int `xml:"directed,attr"`
	RootNode   int `xml:"Rootnode,attr,omitempty"`
}
type XGMMLNode struct {
	XMLName    xml.Name `xml:"node"`
	Label      string   `xml:"label,attr"`
	Attributes []XGMMLAttribute
	Weight     int           `xml:"weight,attr,omitempty"`
	Id         engine.NodeID `xml:"id,attr"`
}
type XGMMLEdge struct {
	XMLName    xml.Name `xml:"edge"`
	Label      string   `xml:"label,attr"`
	Attributes []XGMMLAttribute
	Source     engine.NodeID `xml:"source,attr"`
	Target     engine.NodeID `xml:"target,attr"`
}
type XGMMLAttribute struct {
	XMLName xml.Name `xml:"att"`
	Name    string   `xml:"name,attr"`
	Value   string   `xml:"value,attr"`
}
