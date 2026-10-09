package analyze

import (
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// TestDatasetDenyReasons loads the dataset in ADALANCHE_TEST_DATA (AD data
// only) and checks every ACL rule grant on objects whose DACL has a deny
// entry. It compares the rule before trustee tokens, where only a deny for
// the trustee itself counted, with the current one, and prints why each
// grant is now refused, as "DENY" lines with counts only. A grant that only
// the current rule allows is a bug.
func TestDatasetDenyReasons(t *testing.T) {
	path := os.Getenv("ADALANCHE_TEST_DATA")
	if path == "" {
		t.Skip("ADALANCHE_TEST_DATA is not set")
	}
	ao, err := engine.Run(path)
	if err != nil {
		t.Fatal("loading failed")
	}

	// keepDenies returns the DACL with every deny ACE that keep rejects
	// made inert, so ACE indexes stay the same.
	keepDenies := func(acl engine.ACL, keep func(engine.ACE) bool) engine.ACL {
		entries := slices.Clone(acl.Entries)
		for i, e := range entries {
			if (e.Type == engine.ACETYPE_ACCESS_DENIED || e.Type == engine.ACETYPE_ACCESS_DENIED_OBJECT) && !keep(e) {
				entries[i].Type = engine.ACEType(0x02) // audit: neither allows nor denies
			}
		}
		acl.Entries = entries
		return acl
	}

	aceCounts := map[[2]string]int{}
	edgeCounts := map[[2]string]int{}
	var objects int
	ao.Iterate(func(o *engine.Node) bool {
		sd, err := o.SecurityDescriptor()
		if err != nil || !slices.ContainsFunc(sd.DACL.Entries, func(e engine.ACE) bool {
			return e.Type == engine.ACETYPE_ACCESS_DENIED || e.Type == engine.ACETYPE_ACCESS_DENIED_OBJECT
		}) {
			return true
		}
		objects++
		objectType := o.Type()
		for _, rule := range aclEdgeRules {
			if len(rule.types) > 0 && !slices.Contains(rule.types, objectType) {
				continue
			}
			// Per trustee: was an edge granted before, and is it now?
			type grant struct {
				before, after bool
				reason       string
			}
			grants := map[windowssecurity.SID]*grant{}
			for index, ace := range sd.DACL.Entries {
				if ace.Type != engine.ACETYPE_ACCESS_ALLOWED && ace.Type != engine.ACETYPE_ACCESS_ALLOWED_OBJECT {
					continue
				}
				trustee := ace.SID
				only := func(sids ...windowssecurity.SID) func(engine.ACE) bool {
					return func(d engine.ACE) bool { return d.SID == trustee || slices.Contains(sids, d.SID) }
				}
				before := keepDenies(sd.DACL, only()).IsObjectClassAccessAllowedFor(index, o, rule.mask, rule.guid, ao, nil)
				after := ACEGrants(ao, sd, index, o, rule.mask, rule.guid)
				g := grants[trustee]
				if g == nil {
					g = &grant{}
					grants[trustee] = g
				}
				g.before = g.before || before
				g.after = g.after || after

				var reason string
				switch {
				case before == after:
					continue
				case after:
					reason = "BUG: granted only by the current rule"
				case !keepDenies(sd.DACL, only(windowssecurity.EveryoneSID)).IsObjectClassAccessAllowedFor(index, o, rule.mask, rule.guid, ao, nil):
					reason = "deny for Everyone"
				case !keepDenies(sd.DACL, only(windowssecurity.EveryoneSID, windowssecurity.AuthenticatedUsersSID)).IsObjectClassAccessAllowedFor(index, o, rule.mask, rule.guid, ao, TrusteeToken(ao, sd, trustee, o)):
					reason = "deny for Authenticated Users, a member of it"
				case !ACEGrants(ao, sd, index, o, rule.mask, rule.guid):
					reason = "deny for a group the trustee is a member of"
				default:
					reason = "BUG: refused without a matching deny"
				}
				aceCounts[[2]string{rule.edge.String(), reason}]++
				if g.reason == "" {
					g.reason = reason
				}
			}
			for _, g := range grants {
				switch {
				case g.before && !g.after:
					edgeCounts[[2]string{rule.edge.String(), "edge removed: " + g.reason}]++
				case g.after && !g.before:
					edgeCounts[[2]string{rule.edge.String(), "BUG: edge added"}]++
				}
			}
		}
		return true
	})

	fmt.Printf("DENY objects_with_deny_aces %d\n", objects)
	for _, counts := range []map[[2]string]int{aceCounts, edgeCounts} {
		keys := make([][2]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, b [2]string) int { return counts[b] - counts[a] })
		for _, k := range keys {
			fmt.Printf("DENY %8d %-32s %s\n", counts[k], k[0], k[1])
		}
	}
}
