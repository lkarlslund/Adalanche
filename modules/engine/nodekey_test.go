package engine_test

import (
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// A node's key finds it again, by distinguished name, GUID or SID, in that
// order of preference.
func TestNodeKeyFindsTheNode(t *testing.T) {
	g := engine.NewIndexedGraph()
	guid := uuid.Must(uuid.NewV4())
	sid := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1105")
	byDN := enginetest.AddNew(g, engine.DistinguishedName, "CN=Alice,DC=example,DC=com", engine.ObjectGUID, guid, engine.ObjectSid, sid)
	byGUID := enginetest.AddNew(g, engine.ObjectGUID, uuid.Must(uuid.NewV4()))
	bySID := enginetest.AddNew(g, engine.ObjectSid, windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1106"))
	none := enginetest.AddNew(g, engine.Name, "nameless")

	for _, c := range []struct {
		node   *engine.Node
		prefix string
	}{{byDN, "distinguishedName="}, {byGUID, "objectGUID="}, {bySID, "objectSid="}} {
		key := engine.NodeKey(c.node)
		if len(key) <= len(c.prefix) || key[:len(c.prefix)] != c.prefix {
			t.Errorf("key %q, want it to start %q", key, c.prefix)
			continue
		}
		nodes, err := g.FindByKey(key)
		if err != nil || nodes.Len() != 1 || nodes.First() != c.node {
			t.Errorf("%v found %v nodes (%v)", key, nodes.Len(), err)
		}
	}
	if key := engine.NodeKey(none); key != "" {
		t.Errorf("a node with no identity has key %q", key)
	}
	for _, bad := range []string{"", "objectSid", "=x", "nosuchattribute=x", "objectSid=not-a-sid", "objectGUID=not-a-guid"} {
		if _, err := g.FindByKey(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}
