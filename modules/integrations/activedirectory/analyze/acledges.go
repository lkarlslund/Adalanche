package analyze

import (
	"slices"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// aclEdgeRule turns one right on an object into an edge from every trustee
// whose ACE grants it.
type aclEdgeRule struct {
	edge  engine.Edge
	mask  engine.Mask
	guid  uuid.UUID         // attribute, property set or extended right; nil for the whole object
	types []engine.NodeType // object types the rule applies to; empty for all
}

var aclEdgeRules = []aclEdgeRule{
	// Rights on any object.
	{edge: activedirectory.EdgeGenericAll, mask: engine.RIGHT_GENERIC_ALL},
	{edge: activedirectory.EdgeWriteAll, mask: engine.RIGHT_GENERIC_WRITE},
	{edge: activedirectory.EdgeWritePropertyAll, mask: engine.RIGHT_DS_WRITE_PROPERTY},
	{edge: activedirectory.EdgeWriteExtendedAll, mask: engine.RIGHT_DS_WRITE_PROPERTY_EXTENDED},
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
	{edge: activedirectory.EdgeTakeOwnership, mask: engine.RIGHT_WRITE_OWNER},
	{edge: activedirectory.EdgeWriteDACL, mask: engine.RIGHT_WRITE_DACL},
	{edge: activedirectory.EdgeAllExtendedRights, mask: engine.RIGHT_DS_CONTROL_ACCESS},

	// Accounts.
	{edge: activedirectory.EdgeResetPassword, mask: engine.RIGHT_DS_CONTROL_ACCESS, guid: ResetPwd,
		types: []engine.NodeType{engine.NodeTypeUser, engine.NodeTypeComputer}},
	// https://blog.harmj0y.net/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/
	{edge: activedirectory.EdgeWriteAllowedToAct, mask: engine.RIGHT_DS_WRITE_PROPERTY, guid: AttributeAllowedToActOnBehalfOfOtherIdentity,
		types: []engine.NodeType{engine.NodeTypeUser, engine.NodeTypeComputer}},
	{edge: activedirectory.EdgeWriteKeyCredentialLink, mask: engine.RIGHT_DS_WRITE_PROPERTY, guid: AttributeMSDSKeyCredentialLink,
		types: []engine.NodeType{engine.NodeTypeUser, engine.NodeTypeComputer}},
	{edge: activedirectory.EdgeWriteSPN, mask: engine.RIGHT_DS_WRITE_PROPERTY, guid: ValidateWriteSPN,
		types: []engine.NodeType{engine.NodeTypeUser}},
	{edge: activedirectory.EdgeWriteValidatedSPN, mask: engine.RIGHT_DS_WRITE_PROPERTY_EXTENDED, guid: ValidateWriteSPN,
		types: []engine.NodeType{engine.NodeTypeUser}},
	{edge: activedirectory.EdgeWriteAltSecurityIdentities, mask: engine.RIGHT_DS_WRITE_PROPERTY, guid: AttributeAltSecurityIdentitiesGUID,
		types: []engine.NodeType{engine.NodeTypeUser}},
	{edge: activedirectory.EdgeWriteProfilePath, mask: engine.RIGHT_DS_WRITE_PROPERTY, guid: AttributeProfilePathGUID,
		types: []engine.NodeType{engine.NodeTypeUser}},
	{edge: activedirectory.EdgeWriteScriptPath, mask: engine.RIGHT_DS_WRITE_PROPERTY, guid: AttributeScriptPathGUID,
		types: []engine.NodeType{engine.NodeTypeUser}},
	{edge: activedirectory.EdgeWriteUserAccountControl, mask: engine.RIGHT_DS_WRITE_PROPERTY, guid: AttributeUserAccountControlGUID,
		types: []engine.NodeType{engine.NodeTypeUser}},
	{edge: activedirectory.EdgeReadPasswordId, mask: engine.RIGHT_DS_READ_PROPERTY, guid: AttributeMSDSManagedPasswordId,
		types: []engine.NodeType{engine.NodeTypeGroupManagedServiceAccount}},

	// Groups.
	{edge: activedirectory.EdgeAddMember, mask: engine.RIGHT_DS_WRITE_PROPERTY, guid: AttributeMember,
		types: []engine.NodeType{engine.NodeTypeGroup}},
	{edge: activedirectory.EdgeAddSelfMember, mask: engine.RIGHT_DS_WRITE_PROPERTY_EXTENDED, guid: ValidateWriteSelfMembership,
		types: []engine.NodeType{engine.NodeTypeGroup}},

	// Certificate templates (MS-CRTD 2.2).
	{edge: activedirectory.EdgeCertificateEnroll, mask: engine.RIGHT_DS_CONTROL_ACCESS, guid: ExtendedRightCertificateEnroll,
		types: []engine.NodeType{engine.NodeTypeCertificateTemplate}},
	{edge: activedirectory.EdgeCertificateAutoEnroll, mask: engine.RIGHT_DS_CONTROL_ACCESS, guid: ExtendedRightCertificateAutoEnroll,
		types: []engine.NodeType{engine.NodeTypeCertificateTemplate}},

	// Schema. Experimental: changing an attribute's property set can move it
	// to a weaker one.
	{edge: activedirectory.EdgeWriteAttributeSecurityGUID, mask: engine.RIGHT_DS_WRITE_PROPERTY, guid: AttributeSecurityGUIDGUID,
		types: []engine.NodeType{engine.NodeTypeAttributeSchema}},
}

// addACLRuleEdges reads every object's security descriptor once and adds an
// edge for each rule an ACE grants, from the ACE's trustee to the object.
func addACLRuleEdges(tx *engine.Tx) {
	var rules []aclEdgeRule
	tx.Iterate(func(o *engine.Node) bool {
		sd, err := o.SecurityDescriptor()
		if err != nil {
			return true
		}
		objectType := o.Type()
		rules = rules[:0]
		for _, rule := range aclEdgeRules {
			if len(rule.types) == 0 || slices.Contains(rule.types, objectType) {
				rules = append(rules, rule)
			}
		}
		for index, ace := range sd.DACL.Entries {
			if ace.Type != engine.ACETYPE_ACCESS_ALLOWED && ace.Type != engine.ACETYPE_ACCESS_ALLOWED_OBJECT {
				continue
			}
			var granted engine.EdgeBitmap
			for _, rule := range rules {
				// A grant needs every requested bit in this one ACE, so
				// skip the full check when they are not all there.
				if ace.Mask&rule.mask == rule.mask && ACEGrants(tx, sd, index, o, rule.mask, rule.guid) {
					granted = granted.Set(rule.edge)
				}
			}
			if granted.IsBlank() {
				continue
			}
			trustee := aceTrustee(tx, sd, ace.SID, o)
			// The same exclusions as EdgeTo: no edges to itself, from SELF,
			// or between nodes for the same SID.
			if t := trustee.Node(); t == o || t.SID() == windowssecurity.SelfSID || (!t.SID().IsBlank() && t.SID() == o.SID()) {
				continue
			}
			tx.SetEdgeBecause(trustee, o, granted, ACECause(index, ace))
		}
		return true
	})
}
