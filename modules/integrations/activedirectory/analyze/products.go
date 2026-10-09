package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// Products made by the Active Directory processors. Processors that use one
// list it in Needs and run after every processor that provides it.
const (
	// Node types derived from objectClass and objectCategory.
	ProductNodeTypes engine.Product = "ad/node-types"
	// The DomainContext attribute: the naming context an object lives in.
	ProductDomainContext engine.Product = "ad/domain-context"
	// The DOMAIN\name DownLevelLogonName attribute.
	ProductDownLevelLogonName engine.Product = "ad/down-level-logon-name"
	// Nodes for well-known and builtin SIDs in every domain.
	ProductWellKnownPrincipals engine.Product = "ad/well-known-principals"
	// Display names for well-known SID nodes.
	ProductWellKnownDisplayNames engine.Product = "ad/well-known-display-names"
	// Machine nodes for computer accounts, linked by DomainJoinedSID.
	ProductMachines engine.Product = "ad/machines"
	// Parent and child links following distinguished names.
	ProductTree engine.Product = "ad/tree"
	// Account state tags (enabled, disabled, delegation, domain controller
	// roles and so on) and trust information.
	ProductAccountState engine.Product = "ad/account-state"
	// MemberOfGroup edges: primary groups, memberOf and member, and the
	// implicit Authenticated Users and Enterprise Domain Controllers ones.
	ProductMemberships engine.Product = "ad/memberships"
	// The indirect memberOf attribute derived from memberships.
	ProductIndirectMemberships engine.Product = "ad/indirect-memberships"
	// Edges derived from security descriptors: ownership, rights and the
	// attacks they enable.
	ProductACLEdges engine.Product = "ad/acl-edges"
	// Edges and tags for attacks on account settings, such as Kerberoasting
	// and AS-REP roasting.
	ProductAccountAttacks engine.Product = "ad/account-attacks"
	// Delegation edges (constrained and resource-based).
	ProductDelegation engine.Product = "ad/delegation"
	// Links between accounts and services, machines and SID history.
	ProductAccountLinks engine.Product = "ad/account-links"
	// GPO structure: configuration containers that are part of a GPO.
	ProductGPOStructure engine.Product = "ad/gpo-structure"
	// AffectedByGPO edges from GPOs to the machines and users they apply to.
	ProductGPOTargeting engine.Product = "ad/gpo-targeting"
	// Local group members given by GPOs.
	ProductGPOLocalGroups engine.Product = "ad/gpo-local-groups"
	// Edges from AdminSDHolder to the objects whose ACLs it overwrites.
	ProductAdminSDHolder engine.Product = "ad/adminsdholder"
	// The protected_user tag.
	ProductProtectedUsers engine.Product = "ad/protected-users"
	// Certificate template publishing status and CA roles.
	ProductCertificateTemplates engine.Product = "ad/certificate-templates"
	// Tags for references to objects that do not exist, such as GPO links
	// to deleted GPOs.
	ProductConfigurationFindings engine.Product = "ad/configuration-findings"
)

// MachinesForComputer returns every machine linked to the computer account
// with the given SID: the machine made from the directory and every machine
// collection claiming the account.
func MachinesForComputer(r engine.GraphReader, computerSID windowssecurity.SID) []*engine.Node {
	var machines []*engine.Node
	if found, ok := r.FindMulti(DomainJoinedSID, engine.NV(computerSID)); ok {
		found.Iterate(func(n *engine.Node) bool {
			if n.Type() == ObjectTypeMachine {
				machines = append(machines, n)
			}
			return true
		})
	}
	return machines
}
