package analyze

import "encoding/xml"

// type XGMML struct {
// 	XMLNAme xml.Name `xml:"graph"`
// 	Graph   XGMMLGraph
// }

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

	Directed int    `xml:"directed,attr"`
	Label    string `xml:"label,attr,omitempty"`
	RootNode int    `xml:"Rootnode,attr,omitempty"`

	Nodes []XGMMLNode
	Edges []XGMMLEdge
}

type XGMMLNode struct {
	XMLName    xml.Name `xml:"node"`
	Id         uint32   `xml:"id,attr"`
	Label      string   `xml:"label,attr"`
	Weight     int      `xml:"weight,attr,omitempty"`
	Attributes []XGMMLAttribute
}

type XGMMLEdge struct {
	XMLName    xml.Name `xml:"edge"`
	Source     uint32   `xml:"source,attr"`
	Target     uint32   `xml:"target,attr"`
	Label      string   `xml:"label,attr"`
	Attributes []XGMMLAttribute
}

type XGMMLAttribute struct {
	XMLName xml.Name `xml:"att"`
	Name    string   `xml:"name,attr"`
	Value   string   `xml:"value,attr"`
}
