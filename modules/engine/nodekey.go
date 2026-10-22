package engine

import (
	"fmt"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// A node key names a node by its primary identity, as "attribute=value"
// (such as distinguishedName=CN=x,DC=example,DC=com or objectSid=S-1-5-...).
// Node ids change whenever the graph loads again; keys hold across loads, so
// they are what to store about a node. A SID is not always unique (built-in
// SIDs exist once per machine), so whoever stores a key should check that it
// finds just the one node.

// NodeKey returns a node's key, or "" when it has no primary identity.
func NodeKey(o *Node) string {
	attr, value := o.PrimaryID()
	if attr == NonExistingAttribute || value.IsNil() {
		return ""
	}
	return attr.String() + "=" + value.String()
}

// ParseNodeKey reads a key into the attribute and the value to find it by.
func ParseNodeKey(key string) (Attribute, AttributeValue, error) {
	name, text, found := strings.Cut(key, "=")
	if !found || name == "" || text == "" {
		return NonExistingAttribute, AttributeValue{}, fmt.Errorf("%q is not a key: keys look like objectSid=<SID>", key)
	}
	attr := LookupAttribute(name)
	if attr == NonExistingAttribute {
		return NonExistingAttribute, AttributeValue{}, fmt.Errorf("unknown attribute %q", name)
	}
	var value AttributeValue = NV(text)
	switch attr {
	case ObjectSid:
		sid, err := windowssecurity.ParseStringSID(text)
		if err != nil {
			return NonExistingAttribute, AttributeValue{}, err
		}
		value = NV(sid)
	case ObjectGUID:
		guid, err := uuid.FromString(text)
		if err != nil {
			return NonExistingAttribute, AttributeValue{}, err
		}
		value = NV(guid)
	}
	return attr, value, nil
}

// FindByKey returns the nodes a key names: one, normally.
func (os *IndexedGraph) FindByKey(key string) (NodeSlice, error) {
	attr, value, err := ParseNodeKey(key)
	if err != nil {
		return NodeSlice{}, err
	}
	nodes, _ := os.FindMulti(attr, value)
	return nodes, nil
}
