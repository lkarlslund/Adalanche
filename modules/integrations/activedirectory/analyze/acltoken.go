package analyze

import (
	"cmp"
	"fmt"
	"slices"
	"sync"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// trusteeTokens caches memberSIDs per trustee node. ACL edges are built after
// group memberships are resolved, and the cache is released once analysis is
// done.
var trusteeTokens sync.Map // *engine.Node -> map[windowssecurity.SID]struct{}

// tokenClosures caches the SIDs of the groups reachable from a set of
// direct groups, by the set (and the machine the principal is local to).
var tokenClosures sync.Map // string -> map[windowssecurity.SID]struct{}

// ACEGrants reports whether the ACE at index in the DACL of sd grants mask for
// guid on o, and no preceding deny ACE refuses any of it to its trustee: one
// for the trustee itself, for Everyone, or for a group in the trustee's token.
func ACEGrants(ao engine.GraphReader, sd *engine.SecurityDescriptor, index int, o *engine.Node, mask engine.Mask, guid uuid.UUID) bool {
	return sd.DACL.IsObjectClassAccessAllowedFor(index, o, mask, guid, ao.Graph(), TrusteeToken(ao, sd, sd.DACL.Entries[index].SID, o))
}

// TrusteeGranted reports whether the trustee's own ACEs grant all of mask
// for guid on o, counting rights spread over several ACEs, with denies
// counted as in ACEGrants.
func TrusteeGranted(ao engine.GraphReader, sd *engine.SecurityDescriptor, sid windowssecurity.SID, o *engine.Node, mask engine.Mask, guid uuid.UUID) bool {
	return sd.TrusteeAccessCheck(sid, TrusteeToken(ao, sd, sid, o), o, mask, guid, ao.Graph())
}

// TrusteeToken returns a membership test for SIDs that are in the token of
// everyone who acts as the trustee sid in an ACL on o: the groups the trustee
// is a member of, directly or through nesting, following MemberOfGroup edges.
// A deny for any of them refuses a grant to the trustee for all of its
// members. The token is built on first use, as most ACLs have no denies.
func TrusteeToken(ao engine.GraphReader, sd *engine.SecurityDescriptor, sid windowssecurity.SID, o *engine.Node) func(windowssecurity.SID) bool {
	var token map[windowssecurity.SID]struct{}
	return func(member windowssecurity.SID) bool {
		if token == nil {
			token = map[windowssecurity.SID]struct{}{}
			if sid == windowssecurity.OwnerSID && sd != nil && !sd.Owner.IsNull() {
				sid = sd.Owner
			}
			if trustee, found := ao.FindAdjacentSID(sid, o); found {
				if cached, found := trusteeTokens.Load(trustee); found {
					token = cached.(map[windowssecurity.SID]struct{})
				} else {
					token = memberSIDs(ao, trustee)
					trusteeTokens.Store(trustee, token)
				}
			}
		}
		_, found := token[member]
		return found
	}
}

// membershipGraph is what memberSIDs needs from a graph, so it works on both
// the graph and a frozen view of it.
type membershipGraph interface {
	EdgeIteratorRecursive(node *engine.Node, direction engine.EdgeDirection, edgeMatch engine.EdgeBitmap, excludemyself bool, goDeeperFunc func(source, target *engine.Node, edge engine.EdgeBitmap, depth int) bool)
}

// memberSIDs returns the SIDs of every group n is a member of, directly or
// through nesting.
func memberSIDs(g membershipGraph, n *engine.Node) map[windowssecurity.SID]struct{} {
	return memberSIDsCached(g, n, &tokenClosures)
}

// memberSIDsCached is memberSIDs with the group closures cached in closures.
func memberSIDsCached(g membershipGraph, n *engine.Node, closures *sync.Map) map[windowssecurity.SID]struct{} {
	home := machineOf(n)
	memberOf := engine.EdgeBitmap{}.Set(activedirectory.EdgeMemberOfGroup)
	// A machine's local groups are in a token only on that machine: the
	// domain's Authenticated Users is a member of every joined machine's,
	// which no directory token includes.
	outside := func(group *engine.Node) bool {
		local := machineOf(group)
		return local != nil && local != home
	}
	var direct []*engine.Node
	g.EdgeIteratorRecursive(n, engine.Out, memberOf, true, func(_, group *engine.Node, _ engine.EdgeBitmap, _ int) bool {
		if !outside(group) {
			direct = append(direct, group)
		}
		return false
	})
	// Most principals share their direct groups (every computer is in
	// Domain Computers and Authenticated Users), so the closure is walked
	// once per distinct set of them.
	slices.SortFunc(direct, func(a, b *engine.Node) int { return cmp.Compare(a.ID(), b.ID()) })
	var key string
	if home == nil {
		key = fmt.Sprint(engine.InvalidNodeID, nodeIDs(direct))
	} else {
		key = fmt.Sprint(home.ID(), nodeIDs(direct))
	}
	if cached, found := closures.Load(key); found {
		return cached.(map[windowssecurity.SID]struct{})
	}
	sids := map[windowssecurity.SID]struct{}{}
	for _, group := range direct {
		if sid := group.SID(); !sid.IsBlank() {
			sids[sid] = struct{}{}
		}
		g.EdgeIteratorRecursive(group, engine.Out, memberOf, true, func(_, nested *engine.Node, _ engine.EdgeBitmap, _ int) bool {
			if outside(nested) {
				return false
			}
			if sid := nested.SID(); !sid.IsBlank() {
				sids[sid] = struct{}{}
			}
			return true
		})
	}
	closures.Store(key, sids)
	return sids
}

func nodeIDs(nodes []*engine.Node) []engine.NodeID {
	ids := make([]engine.NodeID, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID()
	}
	return ids
}

// machineOf returns the machine a node is local to: the machine it is placed
// under, or the node itself when it is a machine.
func machineOf(n *engine.Node) *engine.Node {
	if n.Type() == ObjectTypeMachine {
		return n
	}
	if p := n.Parent(); p != nil && p.Type() == ObjectTypeMachine {
		return p
	}
	return nil
}

func init() {
	// Tokens hold memberships as they were when built: they are released
	// once each phase is done, so the analysis phase never sees tokens from
	// before references were resolved.
	for _, phase := range []engine.Phase{engine.LoaderPhase, engine.AnalysisPhase} {
		LoaderID.AddProcessor(func(tx *engine.Tx) {
			trusteeTokens.Clear()
			tokenClosures.Clear()
		}, engine.Processor{
			Description: "Release cached trustee tokens",
			Phase:       phase,
			Final:       true,
		})
	}
}
