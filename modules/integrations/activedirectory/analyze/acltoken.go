package analyze

import (
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
	sids := map[windowssecurity.SID]struct{}{}
	g.EdgeIteratorRecursive(n, engine.Out, engine.EdgeBitmap{}.Set(activedirectory.EdgeMemberOfGroup), true, func(_, group *engine.Node, _ engine.EdgeBitmap, _ int) bool {
		if sid := group.SID(); !sid.IsBlank() {
			sids[sid] = struct{}{}
		}
		return true
	})
	return sids
}

func init() {
	LoaderID.AddProcessor(func(tx *engine.Tx) {
		trusteeTokens.Clear()
	}, engine.Processor{
		Description: "Release cached trustee tokens",
		Phase:       engine.AfterMerge,
		Final:       true,
	})
}
