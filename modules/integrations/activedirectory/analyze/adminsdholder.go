package analyze

import (
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
)

// adminSDHolderExclusions reads dwAdminSDExMask, the 16th dSHeuristics
// character: a hex digit whose bits exclude Account, Server, Print and
// Backup Operators from protection (MS-ADTS 3.1.1.6.1.4).
func adminSDHolderExclusions(heuristics string) int {
	if len(heuristics) < 16 {
		return 0
	}
	return max(strings.Index("0123456789abcdef", strings.ToLower(heuristics[15:16])), 0)
}

// addAdminSDHolderEdges marks the objects whose security descriptor the
// AdminSDHolder of their domain overwrites (MS-ADTS 3.1.1.6.1.2): security
// principals of the domain that are direct or nested members of the
// administrative groups, plus the Administrator and krbtgt accounts and the
// Domain Controllers and Read-only Domain Controllers groups themselves.
// It needs group memberships, so it runs after they are resolved.
func addAdminSDHolderEdges(tx *engine.Tx) {
	var holders []*engine.Node
	tx.Iterate(func(o *engine.Node) bool {
		if strings.HasPrefix(strings.ToLower(o.DN()), "cn=adminsdholder,cn=system,") {
			holders = append(holders, o)
		}
		return true
	})

	member := engine.EdgeBitmap{}.Set(activedirectory.EdgeMemberOfGroup)
	for _, holder := range holders {
		domainContext := holder.OneAttrString(engine.DomainContext)
		domain, found := tx.Find(engine.DistinguishedName, engine.NV(domainContext))
		if !found || domain.SID().IsBlank() {
			continue
		}
		domainSID := domain.SID()
		inDomain := func(o *engine.Node) bool {
			sid := o.SID()
			return !sid.IsBlank() && sid.Components() > 4 && sid.StripRID() == domainSID
		}
		excluded := adminSDHolderExclusions(forestHeuristics(tx, domainContext))
		inForest := func(o *engine.Node) bool {
			// The group's domain is the root of this domain's forest.
			return engine.InForest(tx, domainContext, o.OneAttrString(engine.DomainContext))
		}

		// Collect first and add the edges afterwards: walking memberships
		// holds the edge lock, so edges cannot be added during the walk.
		var protected []*engine.Node
		protect := func(o *engine.Node) {
			protected = append(protected, o)
		}
		protectInDomain := func(group *engine.Node) {
			tx.EdgeIteratorRecursive(group, engine.In, member, true, func(_, m *engine.Node, _ engine.EdgeBitmap, _ int) bool {
				if inDomain(m) {
					protect(m)
				}
				return true
			})
		}
		protectMembers := func(group *engine.Node) {
			protect(group)
			protectInDomain(group)
		}

		tx.Iterate(func(o *engine.Node) bool {
			sid := o.SID()
			if sid.IsBlank() || sid.Components() < 3 {
				return true
			}
			sameDomain := strings.EqualFold(o.OneAttrString(engine.DomainContext), domainContext)
			builtin := sid.Component(2) == 32 && sid.Components() == 4
			rid := sid.RID()
			switch {
			case builtin && sameDomain && o.Type() == engine.NodeTypeGroup:
				switch rid {
				case DOMAIN_ALIAS_RID_ADMINS, DOMAIN_ALIAS_RID_REPLICATOR:
					protectMembers(o)
				case DOMAIN_ALIAS_RID_ACCOUNT_OPS:
					if excluded&1 == 0 {
						protectMembers(o)
					}
				case DOMAIN_ALIAS_RID_SYSTEM_OPS:
					if excluded&2 == 0 {
						protectMembers(o)
					}
				case DOMAIN_ALIAS_RID_PRINT_OPS:
					if excluded&4 == 0 {
						protectMembers(o)
					}
				case DOMAIN_ALIAS_RID_BACKUP_OPS:
					if excluded&8 == 0 {
						protectMembers(o)
					}
				}
			case sid.Component(2) == 21 && o.Type() == engine.NodeTypeGroup:
				switch rid {
				case DOMAIN_GROUP_RID_ADMINS:
					if inDomain(o) {
						protectMembers(o)
					}
				case DOMAIN_GROUP_RID_SCHEMA_ADMINS, DOMAIN_GROUP_RID_ENTERPRISE_ADMINS:
					// Forest-wide groups in the forest's root domain: the root
					// domain's AdminSDHolder protects the group, and each
					// domain's protects its members of it. Other forests'
					// groups are not this domain's concern.
					if !inForest(o) {
						break
					}
					if inDomain(o) {
						protect(o)
					}
					protectInDomain(o)
				case DOMAIN_GROUP_RID_CONTROLLERS, DOMAIN_GROUP_RID_READONLY_CONTROLLERS:
					if inDomain(o) {
						protect(o)
					}
				}
			case sid.Component(2) == 21 && inDomain(o) && (rid == DOMAIN_USER_RID_ADMIN || rid == DOMAIN_USER_RID_KRBTGT):
				protect(o)
			}
			return true
		})
		for _, o := range protected {
			tx.EdgeBecause(holder, o, activedirectory.EdgeOverwritesACL, Inferred("AdminSDHolder protects this account or group"))
		}
	}
}
