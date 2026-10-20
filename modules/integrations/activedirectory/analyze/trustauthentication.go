package analyze

import (
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// Trust directions and attributes, as in MS-ADTS 6.1.6.7.
const (
	trustDirectionOutbound = 0x2
	trustCrossOrganization = 0x10 // selective authentication
)

// addTrustAuthentication makes the Authenticated Users of a trusted domain
// members of the trusting domain's Authenticated Users, and so of its
// Everyone: an outbound trust lets the partner's accounts authenticate in the
// trusting domain. With selective authentication only accounts given
// Allowed-To-Authenticate on a resource get in, so such trusts add nothing.
// Both domains must be collected. Linking the domains' Authenticated Users
// also carries the trust on to domains the partner trusts, which overstates
// non-transitive external trusts.
func addTrustAuthentication(tx *engine.Tx) {
	bySID := map[windowssecurity.SID]*engine.Node{}
	byContext := map[string]*engine.Node{}
	dnsRoot := map[*engine.Node]string{}
	for _, domain := range FindDomainNodes(tx) {
		ncname, _, dnsroot, sid, err := GetDomainInfo(domain, tx)
		if err != nil {
			continue
		}
		bySID[sid] = domain
		byContext[strings.ToLower(ncname)] = domain
		dnsRoot[domain] = dnsroot
	}
	tx.Iterate(func(trust *engine.Node) bool {
		if trust.Type() != engine.NodeTypeTrust {
			return true
		}
		direction, _ := trust.AttrInt(activedirectory.TrustDirection)
		attributes, _ := trust.AttrInt(activedirectory.TrustAttributes)
		if direction&trustDirectionOutbound == 0 || attributes&trustCrossOrganization != 0 {
			return true
		}
		trusting, local := byContext[strings.ToLower(trust.OneAttrString(engine.DomainContext))]
		partnerSID, _ := trust.OneAttrRaw(activedirectory.SecurityIdentifier).(windowssecurity.SID)
		trusted, collected := bySID[partnerSID]
		if !local || !collected || trusted == trusting {
			return true
		}
		from, found := tx.FindAdjacentSID(windowssecurity.AuthenticatedUsersSID, trusted)
		if !found {
			return true
		}
		to, found := tx.FindAdjacentSID(windowssecurity.AuthenticatedUsersSID, trusting)
		if !found {
			return true
		}
		// Both are S-1-5-11, so the edge has to be forced.
		tx.EdgeBecauseEx(from, to, activedirectory.EdgeMemberOfGroup, true,
			Inferred(dnsRoot[trusting]+" trusts "+trust.OneAttrString(activedirectory.TrustPartner)+" without selective authentication"))
		return true
	})
}

func init() {
	LoaderID.AddProcessor(addTrustAuthentication,
		engine.Processor{
			Description: "Authenticated Users of trusted domains are Authenticated Users of the trusting domain",
			Phase:       engine.LoaderPhase,
			Needs:       []engine.Product{ProductMemberships},
		})
}
