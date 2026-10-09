package mcpserver

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// Node ids number nodes as the graph loaded them, so they change whenever it
// loads again. Ids given out carry a tag for the load, "123@k3f9", and ids
// with another load's tag, or none, are refused instead of quietly naming
// another node. Keys name nodes by their identity, such as their SID or
// distinguished name, and hold across loads.

// loadTag returns the tag of the graph's load, making one for a graph not
// seen before.
func (s *Server) loadTag(g *engine.IndexedGraph) string {
	s.loadLock.Lock()
	defer s.loadLock.Unlock()
	if g != s.loadGraph || s.load == "" {
		buf := make([]byte, 3)
		rand.Read(buf)
		s.load, s.loadGraph = strings.ToLower(fmt.Sprintf("%x", buf)), g
	}
	return s.load
}

// currentTag is the tag of the graph tools are working on: Graph sets it.
func (s *Server) currentTag() string {
	s.loadLock.Lock()
	defer s.loadLock.Unlock()
	return s.load
}

// NodeBrief names a node.
type NodeBrief struct {
	NodeID string `json:"node_id" jsonschema:"the node in this load of the graph; it changes when the graph loads again"`
	Key    string `json:"key,omitempty" jsonschema:"names the node by its identity, such as objectSid=S-1-5-...; it holds across loads"`
	Label  string `json:"label"`
	Type   string `json:"type"`
}

func (s *Server) nodeID(id engine.NodeID) string {
	return strconv.FormatUint(uint64(id), 10) + "@" + s.currentTag()
}

// key names a node by its primary identity, unless that is a secret.
func key(node *engine.Node) string {
	attr, value := node.PrimaryID()
	if attr == engine.NonExistingAttribute || value.IsNil() || secret(attr) {
		return ""
	}
	return attr.String() + "=" + value.String()
}

// Brief names a node.
func (s *Server) Brief(node *engine.Node) NodeBrief {
	return NodeBrief{NodeID: s.nodeID(node.ID()), Key: key(node), Label: node.Label(), Type: node.Type().Lookup()}
}

func (s *Server) briefOf(node *engine.Node) *NodeBrief {
	if node == nil {
		return nil
	}
	b := s.Brief(node)
	return &b
}

// parseNodeID reads a node id given out by this load of the graph.
func (s *Server) parseNodeID(text string) (engine.NodeID, error) {
	number, tag, tagged := strings.Cut(strings.TrimSpace(text), "@")
	id, err := strconv.ParseUint(strings.TrimPrefix(number, "n"), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%q is not a node id: node ids look like 123@%s", text, s.currentTag())
	}
	switch {
	case !tagged:
		return 0, fmt.Errorf("node id %q has no load tag: use the node_id exactly as a tool gave it (like %d@%s), or the node's key", text, id, s.currentTag())
	case tag != s.currentTag():
		return 0, fmt.Errorf("node id %q is from an earlier load of the graph, and node ids change when it loads again: find the node again, or use its key", text)
	}
	return engine.NodeID(id), nil
}

// lookupKey finds a node by a key, "attribute=value".
func (s *Server) lookupKey(g *engine.IndexedGraph, text string) (*engine.Node, error) {
	name, value, found := strings.Cut(text, "=")
	if !found || name == "" || value == "" {
		return nil, fmt.Errorf("%q is not a key: keys look like objectSid=<SID>", text)
	}
	attr := engine.LookupAttribute(name)
	if attr == engine.NonExistingAttribute {
		return nil, fmt.Errorf("unknown attribute %q", name)
	}
	if secret(attr) {
		return nil, fmt.Errorf("attribute %q holds secrets and cannot be searched", name)
	}
	var lookup engine.AttributeValue = engine.NV(value)
	switch attr {
	case engine.ObjectSid:
		sid, err := windowssecurity.ParseStringSID(value)
		if err != nil {
			return nil, err
		}
		lookup = engine.NV(sid)
	case engine.ObjectGUID:
		guid, err := uuid.FromString(value)
		if err != nil {
			return nil, err
		}
		lookup = engine.NV(guid)
	}
	if node, found := g.Find(attr, lookup); found {
		return node, nil
	}
	return nil, fmt.Errorf("no node with %s", text)
}
