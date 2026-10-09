package analyze

import (
	"strconv"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// aclRuleByEdge finds the rule behind an ACL edge, and aclRuleEdges holds
// every edge the rules make.
var (
	aclRuleByEdge = map[engine.Edge]aclEdgeRule{}
	aclRuleEdges  engine.EdgeBitmap
)

func init() {
	for _, rule := range aclEdgeRules {
		aclRuleByEdge[rule.edge] = rule
		aclRuleEdges = aclRuleEdges.Set(rule.edge)
	}
	engine.RegisterActorChecker(func(g *engine.IndexedGraph) engine.ActorChecker {
		return &actorDenies{g: g, tokens: map[*engine.Node]map[windowssecurity.SID]struct{}{}, holders: map[*engine.Node][]*engine.Node{}, denies: map[*engine.Node][]int{}}
	})
}

// actorDenies finds the denies before a granting ACE that refuse an ACL edge
// to some of the accounts acting through its trustee. The analysis already
// refuses grants to every member of the trustee: denies for the trustee,
// Everyone, or a group the trustee is in. What is left are denies for other
// groups, or for accounts, that only some members are in.
type actorDenies struct {
	g        *engine.IndexedGraph
	tokens   map[*engine.Node]map[windowssecurity.SID]struct{}
	holders  map[*engine.Node][]*engine.Node
	denies   map[*engine.Node][]int // positions of denies not for Everyone
	closures sync.Map
}

func (c *actorDenies) Refusers(from, to *engine.Node, eb engine.EdgeBitmap) []engine.Refusal {
	rules := eb.Intersect(aclRuleEdges)
	if rules.IsBlank() {
		return nil
	}
	sd, err := to.SecurityDescriptor()
	if err != nil {
		return nil
	}
	denies, done := c.denies[to]
	if !done {
		for i, ace := range sd.DACL.Entries {
			if (ace.Type == engine.ACETYPE_ACCESS_DENIED || ace.Type == engine.ACETYPE_ACCESS_DENIED_OBJECT) && ace.SID != windowssecurity.EveryoneSID {
				denies = append(denies, i)
			}
		}
		c.denies[to] = denies
	}
	if len(denies) == 0 {
		return nil
	}

	// The ACEs that grant each edge, as its causes record them.
	grants := map[engine.Edge][]int{}
	for _, p := range c.g.EdgeSources(from, to) {
		if p.Source.Kind != SourceACL || !rules.IsSet(p.Edge) {
			continue
		}
		if index, ok := aceIndex(p.Source.Detail); ok && index < len(sd.DACL.Entries) {
			grants[p.Edge] = append(grants[p.Edge], index)
		}
	}
	var trustee func(windowssecurity.SID) bool

	var result []engine.Refusal
	for edge, indexes := range grants {
		rule := aclRuleByEdge[edge]
		refusal := engine.Refusal{Edge: edge}
		for _, index := range indexes {
			var refusers []windowssecurity.SID
			for _, position := range denies {
				if position >= index {
					break
				}
				ace := sd.DACL.Entries[position]
				if ace.Mask&rule.mask == 0 {
					continue
				}
				if trustee == nil {
					trustee = c.InToken(from)
				}
				if trustee(ace.SID) || !ace.Refuses(to, rule.mask, rule.guid, c.g) {
					continue
				}
				refusers = append(refusers, ace.SID)
			}
			if len(refusers) == 0 {
				refusal.Grants = nil // this grant holds for every account
				break
			}
			refusal.Grants = append(refusal.Grants, refusers)
		}
		if len(refusal.Grants) > 0 {
			result = append(result, refusal)
		}
	}
	return result
}

// InToken returns a test for the SIDs in the token of the principal n: its
// own SID and the groups it is in, directly or through nesting.
func (c *actorDenies) InToken(n *engine.Node) func(windowssecurity.SID) bool {
	token, found := c.tokens[n]
	if !found {
		token = memberSIDsCached(c.g, n, &c.closures)
		c.tokens[n] = token
	}
	sid := n.SID()
	return func(s windowssecurity.SID) bool {
		_, found := token[s]
		return found || (s == sid && !sid.IsBlank())
	}
}

func (c *actorDenies) Holders(sid windowssecurity.SID, relativeTo *engine.Node) []*engine.Node {
	principal, found := c.g.FindAdjacentSID(sid, relativeTo)
	if !found {
		return nil
	}
	if holders, done := c.holders[principal]; done {
		return holders
	}
	holders := []*engine.Node{principal}
	home := machineOf(principal)
	memberOf := engine.EdgeBitmap{}.Set(activedirectory.EdgeMemberOfGroup)
	c.g.EdgeIteratorRecursive(principal, engine.In, memberOf, true, func(_, member *engine.Node, _ engine.EdgeBitmap, _ int) bool {
		// A machine's local group holds only the members on that machine.
		if local := machineOf(member); home != nil && local != nil && local != home {
			return false
		}
		holders = append(holders, member)
		return true
	})
	c.holders[principal] = holders
	return holders
}

// aceIndex reads the index from an ACE cause of the target's own descriptor,
// "ACE 45" or "ACE 45, inherited".
func aceIndex(detail string) (int, bool) {
	rest, found := strings.CutPrefix(detail, "ACE ")
	if !found {
		return 0, false
	}
	if end := strings.IndexByte(rest, ','); end >= 0 {
		rest = rest[:end]
	}
	index, err := strconv.Atoi(rest)
	return index, err == nil
}
