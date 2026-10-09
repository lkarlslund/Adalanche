package aql

import (
	"strconv"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
)

func TestRepresentedCountsMergedAndFoldedNodes(t *testing.T) {
	machine := engine.NewNode(engine.Type, engine.NodeTypeMachine.ValueString())
	group := engine.NewNode(engine.Type, engine.NodeTypeGroup.ValueString())
	user := engine.NewNode(engine.Type, engine.NodeTypeUser.ValueString())
	byID := map[engine.NodeID]*engine.Node{group.ID(): group, user.ID(): user}
	lookup := func(id engine.NodeID) (*engine.Node, bool) {
		n, found := byID[id]
		return n, found
	}
	member := func(n *engine.Node) MergedMember {
		return MergedMember{ID: "n" + strconv.FormatUint(uint64(n.ID()), 10)}
	}

	plain := Represented(user, map[string]any{}, lookup)
	if len(plain) != 1 || plain[engine.NodeTypeUser] != 1 {
		t.Errorf("plain node: %v", plain)
	}

	// Three machines drawn as one, with a local group and account folded in.
	counts := Represented(machine, map[string]any{
		"_merged": 3,
		"_folded": []MergedMember{member(group), member(user), {ID: "n999999"}},
	}, lookup)
	if counts[engine.NodeTypeMachine] != 3 || counts[engine.NodeTypeGroup] != 1 || counts[engine.NodeTypeUser] != 1 || len(counts) != 3 {
		t.Errorf("merged machine: %v", counts)
	}
}
