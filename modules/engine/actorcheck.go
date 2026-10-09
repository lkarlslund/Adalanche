package engine

import (
	"sync"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// An ActorChecker tells which edges a deny refuses to the account using
// them. An edge from a group stands for every member; a deny for one of the
// member's own groups, or for the member itself, can refuse it to that member
// alone, which an edge cannot show. Queries ask once they know which account
// a route acts as.
type ActorChecker interface {
	// Refusers returns the edge types of eb from from to to that a deny can
	// refuse to some account acting as from, with the SIDs whose denies
	// refuse each grant; nil when there are none, as for most edges.
	Refusers(from, to *Node, eb EdgeBitmap) []Refusal
	// InToken returns a test for the SIDs in actor's token: its own and
	// those of the groups it is in.
	InToken(actor *Node) func(windowssecurity.SID) bool
	// Holders returns the principals whose token holds sid, as seen from
	// relativeTo: the principal itself and every member, directly or
	// through nesting.
	Holders(sid windowssecurity.SID, relativeTo *Node) []*Node
}

// Refusal is an edge type that some accounts are refused. Each grant of the
// edge lists the SIDs whose denies refuse it; an account is refused the edge
// when its token holds one of them for every grant.
type Refusal struct {
	Edge   Edge
	Grants [][]windowssecurity.SID
}

// RefusedTo reports whether the edge is refused to a token.
func (r Refusal) RefusedTo(inToken func(windowssecurity.SID) bool) bool {
	for _, refusers := range r.Grants {
		refused := false
		for _, sid := range refusers {
			if inToken(sid) {
				refused = true
				break
			}
		}
		if !refused {
			return false
		}
	}
	return len(r.Grants) > 0
}

var (
	actorCheckersLock sync.Mutex
	actorCheckers     []func(*IndexedGraph) ActorChecker
)

// RegisterActorChecker adds a maker of ActorCheckers, called once per query
// so a checker can cache what it learns about the graph.
func RegisterActorChecker(make func(*IndexedGraph) ActorChecker) {
	actorCheckersLock.Lock()
	defer actorCheckersLock.Unlock()
	actorCheckers = append(actorCheckers, make)
}

// NewActorCheckers returns a checker of each registered kind for g.
func NewActorCheckers(g *IndexedGraph) []ActorChecker {
	actorCheckersLock.Lock()
	defer actorCheckersLock.Unlock()
	result := make([]ActorChecker, 0, len(actorCheckers))
	for _, make := range actorCheckers {
		result = append(result, make(g))
	}
	return result
}

// ContainsDeny reports whether the ACL has any deny ACE.
func (a ACL) ContainsDeny() bool {
	if a.containsdeny {
		return true
	}
	for _, ace := range a.Entries {
		if ace.Type == ACETYPE_ACCESS_DENIED || ace.Type == ACETYPE_ACCESS_DENIED_OBJECT {
			return true
		}
	}
	return false
}

// Refuses reports whether the ACE is a deny that refuses any of mask for
// guid on o, to whoever its SID is in the token of.
func (a ACE) Refuses(o *Node, mask Mask, guid uuid.UUID, ao *IndexedGraph) bool {
	if a.Type != ACETYPE_ACCESS_DENIED && a.Type != ACETYPE_ACCESS_DENIED_OBJECT {
		return false
	}
	if a.ACEFlags&ACEFLAG_INHERIT_ONLY_ACE != 0 || a.Mask&mask == 0 {
		return false
	}
	return a.appliesTo(o, guid, ao)
}

// IsActor reports whether n is an account a route can act as. Entering an
// account makes it the one acting; groups and other objects keep the
// account before them.
func IsActor(n *Node) bool {
	switch n.Type() {
	case NodeTypeUser, NodeTypeComputer, NodeTypeGroupManagedServiceAccount, NodeTypeManagedServiceAccount:
		return !n.SID().IsBlank()
	}
	return false
}

// A RouteChecker finds the steps of a route that a deny refuses to the
// account acting there. It caches what it learns, and is not safe for
// concurrent use.
type RouteChecker struct {
	g         *IndexedGraph
	checkers  []ActorChecker
	refusals  map[[2]*Node][]Refusal
	inTokens  map[*Node][]func(windowssecurity.SID) bool
	noDenials bool
}

// NewRouteChecker returns a RouteChecker for g.
func NewRouteChecker(g *IndexedGraph) *RouteChecker {
	checkers := NewActorCheckers(g)
	return &RouteChecker{
		g:         g,
		checkers:  checkers,
		refusals:  map[[2]*Node][]Refusal{},
		inTokens:  map[*Node][]func(windowssecurity.SID) bool{},
		noDenials: len(checkers) == 0,
	}
}

// Refused returns the edge types of eb from from to to that a deny refuses
// to actor, the account acting at from. A route whose acting account is
// not known, as one starting at a group, stands for every member, and
// nothing is refused to it.
func (rc *RouteChecker) Refused(actor, from, to *Node, eb EdgeBitmap) EdgeBitmap {
	var refused EdgeBitmap
	if actor == nil || rc.noDenials {
		return refused
	}
	key := [2]*Node{from, to}
	found, done := rc.refusals[key]
	if !done {
		all, _ := rc.g.GetEdge(from, to)
		for _, c := range rc.checkers {
			found = append(found, c.Refusers(from, to, all.Merge(eb))...)
		}
		rc.refusals[key] = found
	}
	if len(found) == 0 {
		return refused
	}
	tokens, done := rc.inTokens[actor]
	if !done {
		for _, c := range rc.checkers {
			tokens = append(tokens, c.InToken(actor))
		}
		rc.inTokens[actor] = tokens
	}
	for _, r := range found {
		if !eb.IsSet(r.Edge) {
			continue
		}
		for _, inToken := range tokens {
			if r.RefusedTo(inToken) {
				refused = refused.Set(r.Edge)
				break
			}
		}
	}
	return refused
}
