package analyze

import (
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// aceTrustee returns the node an ACE's rights belong to. An ACE for OWNER
// RIGHTS (S-1-3-4) applies to whoever owns the object (MS-DTYP 2.4.2.4).
func aceTrustee(tx *engine.Tx, sd *engine.SecurityDescriptor, sid windowssecurity.SID, o *engine.Node) engine.TxNode {
	if sid == windowssecurity.OwnerSID && sd != nil && !sd.Owner.IsNull() {
		sid = sd.Owner
	}
	return tx.FindOrAddAdjacentSID(sid, o)
}

// hasOwnerRightsACE reports whether the DACL has an effective ACE for OWNER
// RIGHTS. Any such ACE replaces the owner's implicit READ_CONTROL and
// WRITE_DAC rights (MS-DTYP 2.4.2.4).
func hasOwnerRightsACE(sd *engine.SecurityDescriptor) bool {
	for _, ace := range sd.DACL.Entries {
		if ace.SID == windowssecurity.OwnerSID && ace.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE == 0 {
			return true
		}
	}
	return false
}

const directoryServicePrefix = "cn=directory service,cn=windows nt,cn=services,cn=configuration,"

// forestHeuristics finds dSHeuristics for the forest a domain belongs to. It
// lives on CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration
// under the forest root, not under each domain (MS-ADTS 3.1.1.6.1.4).
func forestHeuristics(ao engine.GraphReader, domainDN string) string {
	candidates, _ := ao.FindMulti(engine.Name, engine.NV("Directory Service"))
	var match string
	candidates.Iterate(func(n *engine.Node) bool {
		dn := strings.ToLower(n.DN())
		if !strings.HasPrefix(dn, directoryServicePrefix) {
			return true
		}
		// Only the domain's own forest's settings apply; without them the
		// defaults do.
		if engine.InForest(ao, domainDN, dn[len(directoryServicePrefix):]) {
			match = n.OneAttrString(activedirectory.DsHeuristics)
			return false
		}
		return true
	})
	return match
}

// blocksOwnerImplicitRights reads BlockOwnerImplicitRights, the 29th
// dSHeuristics character. "1" blocks, as does any value other than 0-3,
// which defaults to 1 (MS-ADTS 6.1.1.2.4.1.2, 6.1.3.4). Newer DCs also
// block when it is 0 or unset; the directory does not say which DCs those
// are, so that case is not assumed.
func blocksOwnerImplicitRights(heuristics string) bool {
	if len(heuristics) < 29 {
		return false
	}
	c := heuristics[28]
	return c == '1' || !strings.ContainsRune("0123", rune(c))
}
