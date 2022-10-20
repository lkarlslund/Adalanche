package analyze

import (
	"encoding/binary"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// Interesting permissions on AD
var (
	ResetPwd, _                             = uuid.FromString("{00299570-246d-11d0-a768-00aa006e0529}")
	DSReplicationGetChanges                 = uuid.UUID{0x11, 0x31, 0xf6, 0xaa, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	DSReplicationGetChangesAll              = uuid.UUID{0x11, 0x31, 0xf6, 0xad, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	DSReplicationSyncronize                 = uuid.UUID{0x11, 0x31, 0xf6, 0xab, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	DSReplicationGetChangesInFilteredSet, _ = uuid.FromString("{89e95b76-444d-4c62-991a-0facbeda640c}")

	AttributeMember                                 = uuid.UUID{0xbf, 0x96, 0x79, 0xc0, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	AttributeSetGroupMembership, _                  = uuid.FromString("{BC0AC240-79A9-11D0-9020-00C04FC2D4CF}")
	AttributeSIDHistory                             = uuid.UUID{0x17, 0xeb, 0x42, 0x78, 0xd1, 0x67, 0x11, 0xd0, 0xb0, 0x02, 0x00, 0x00, 0xf8, 0x03, 0x67, 0xc1}
	AttributeAllowedToActOnBehalfOfOtherIdentity, _ = uuid.FromString("{3F78C3E5-F79A-46BD-A0B8-9D18116DDC79}")
	AttributeMSDSGroupMSAMembership                 = uuid.UUID{0x88, 0x8e, 0xed, 0xd6, 0xce, 0x04, 0xdf, 0x40, 0xb4, 0x62, 0xb8, 0xa5, 0x0e, 0x41, 0xba, 0x38}
	AttributeGPLink, _                              = uuid.FromString("{F30E3BBE-9FF0-11D1-B603-0000F80367C1}")
	AttributeMSDSKeyCredentialLink, _               = uuid.FromString("{5B47D60F-6090-40B2-9F37-2A4DE88F3063}")
	AttributeSecurityGUIDGUID, _                    = uuid.FromString("{bf967924-0de6-11d0-a285-00aa003049e2}")
	AttributeAltSecurityIdentitiesGUID, _           = uuid.FromString("{00FBF30C-91FE-11D1-AEBC-0000F80367C1}")
	AttributeProfilePathGUID, _                     = uuid.FromString("{bf967a05-0de6-11d0-a285-00aa003049e2}")
	AttributeScriptPathGUID, _                      = uuid.FromString("{bf9679a8-0de6-11d0-a285-00aa003049e2}")
	AttributeMSDSManagedPasswordId, _               = uuid.FromString("{0e78295a-c6d3-0a40-b491-d62251ffa0a6}")

	ExtendedRightCertificateEnroll, _     = uuid.FromString("{0e10c968-78fb-11d2-90d4-00c04f79dc55}")
	ExtendedRightCertificateAutoEnroll, _ = uuid.FromString("{a05b8cc2-17bc-4802-a710-e7c15ab866a2}")

	ValidateWriteSelfMembership, _ = uuid.FromString("{bf9679c0-0de6-11d0-a285-00aa003049e2}")
	ValidateWriteSPN, _            = uuid.FromString("{f3a64788-5306-11d1-a9c5-0000f80367c1}")

	ObjectGuidUser               = uuid.UUID{0xbf, 0x96, 0x7a, 0xba, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidComputer           = uuid.UUID{0xbf, 0x96, 0x7a, 0x86, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidGroup              = uuid.UUID{0xbf, 0x96, 0x7a, 0x9c, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidDomain             = uuid.UUID{0x19, 0x19, 0x5a, 0x5a, 0x6d, 0xa0, 0x11, 0xd0, 0xaf, 0xd3, 0x00, 0xc0, 0x4f, 0xd9, 0x30, 0xc9}
	ObjectGuidGPO                = uuid.UUID{0xf3, 0x0e, 0x3b, 0xc2, 0x9f, 0xf0, 0x11, 0xd1, 0xb6, 0x03, 0x00, 0x00, 0xf8, 0x03, 0x67, 0xc1}
	ObjectGuidOU                 = uuid.UUID{0xbf, 0x96, 0x7a, 0xa5, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidAttributeSchema, _ = uuid.FromString("{BF967A80-0DE6-11D0-A285-00AA003049E2}")

	AdministratorsSID, _           = windowssecurity.ParseStringSID("S-1-5-32-544")
	BackupOperatorsSID, _          = windowssecurity.ParseStringSID("S-1-5-32-551")
	PrintOperatorsSID, _           = windowssecurity.ParseStringSID("S-1-5-32-550")
	ServerOperatorsSID, _          = windowssecurity.ParseStringSID("S-1-5-32-549")
	EnterpriseDomainControllers, _ = windowssecurity.ParseStringSID("S-1-5-9")

	GPLinkCache = engine.NewAttribute("gpLinkCache")

	EdgePublishesCertificateTemplate = engine.NewEdge("PublishCertTmpl")

	NetBIOSName = engine.NewAttribute("nETBIOSName")
	NCName      = engine.NewAttribute("nCName")
	DNSRoot     = engine.NewAttribute("dnsRoot")

	ObjectTypeMachine   = engine.NewObjectType("Machine", "Machine")
	DomainJoinedSID     = engine.NewAttribute("domainJoinedSid").Merge()
	DnsHostName         = engine.NewAttribute("dnsHostName")
	EdgeAuthenticatesAs = engine.NewEdge("AuthenticatesAs")
	EdgeMachineAccount  = engine.NewEdge("MachineAccount").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability {
		return -1 // Just informative
	}).Describe("Indicates this is the domain joined computer account belonging to the machine")
)

var warnedgpos = make(map[string]struct{})

func init() {
	engine.AddMergeApprover("Only merge Machine objects with other Machine objects", func(a, b *engine.Object) (*engine.Object, error) {
		if a.Type() == ObjectTypeMachine && b.Type() != ObjectTypeMachine {
			return nil, engine.ErrDontMerge
		} else if b.Type() == ObjectTypeMachine && a.Type() != ObjectTypeMachine {
			return nil, engine.ErrDontMerge
		}
		return nil, nil
	})

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Find LAPS or return
		var lapsGUID uuid.UUID
		if lapsobjects, found := ao.FindMulti(engine.Name, engine.AttributeValueString("ms-Mcs-AdmPwd")); found {
			for _, lapsobject := range lapsobjects {
				if lapsobject.HasAttrValue(engine.ObjectClass, engine.AttributeValueString("attributeSchema")) {
					if objectGUID, ok := lapsobject.OneAttrRaw(activedirectory.SchemaIDGUID).(uuid.UUID); ok {
						ui.Debug().Msg("Detected LAPS schema extension GUID")
						lapsGUID = objectGUID
						break
					} else {
						ui.Error().Msgf("Could not read LAPS schema extension GUID from %v", lapsobject.DN())
					}
				}
			}
		}

		if lapsGUID.IsNil() {
			ui.Debug().Msg("Microsoft LAPS not detected, skipping tests for this")
			return
		}

		for _, o := range ao.Slice() {
			// Only for computers
			if o.Type() != engine.ObjectTypeComputer {
				continue
			}

			// ... that has LAPS installed
			if !o.HasAttr(activedirectory.MSmcsAdmPwdExpirationTime) {
				continue
			}

			// Analyze ACL
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}

			// Link to the machine object
			machinesid := o.SID()
			if machinesid.IsBlank() {
				ui.Fatal().Msgf("Computer account %v has no objectSID", o.DN())
			}
			machine, found := ao.Find(DomainJoinedSID, engine.AttributeValueSID(machinesid))
			if !found {
				ui.Error().Msgf("Could not locate machine for domain SID %v", machinesid)
				continue
			}

			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_CONTROL_ACCESS, lapsGUID, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(machine, activedirectory.EdgeReadLAPSPassword)
				}
			}
		}
	}, "Reading local admin passwords via LAPS", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.Type() != engine.ObjectTypeContainer || o.OneAttrString(engine.Name) != "Machine" {
				continue
			}
			// Only for computers, you can't really pwn users this way
			p, hasparent := ao.DistinguishedParent(o)
			if !hasparent || p.Type() != engine.ObjectTypeGroupPolicyContainer {
				continue
			}
			p.EdgeTo(o, activedirectory.PartOfGPO)
		}
	}, "Machine configurations that are part of a GPO", engine.BeforeMergeHigh)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.Type() != engine.ObjectTypeContainer || o.OneAttrString(engine.Name) != "User" {
				continue
			}
			// Only for users, you can't really pwn users this way
			p, hasparent := ao.DistinguishedParent(o)
			if !hasparent || p.Type() != engine.ObjectTypeGroupPolicyContainer {
				continue
			}
			p.EdgeTo(o, activedirectory.PartOfGPO)
		}
	}, "User configurations that are part of a GPO", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// It's a group
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for _, acl := range sd.DACL.Entries {
				if acl.Type == engine.ACETYPE_ACCESS_DENIED || acl.Type == engine.ACETYPE_ACCESS_DENIED_OBJECT {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeACLContainsDeny) // Not a probability of success, this is just an indicator
				}
			}
		}
	}, "Indicator for possible false positives, as the ACL contains DENY entries", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			// https://www.alsid.com/crb_article/kerberos-delegation/
			// --- Citation bloc --- This is generally true, but an exception exists: positioning a Deny for the OWNER RIGHTS SID (S-1-3-4) in an object’s ACE removes the owner’s implicit control of this object’s DACL. ---------------------
			aclhasdeny := false
			for _, ace := range sd.DACL.Entries {
				if ace.Type == engine.ACETYPE_ACCESS_DENIED && ace.SID == windowssecurity.OwnerSID {
					aclhasdeny = true
				}
			}
			if !sd.Owner.IsNull() && !aclhasdeny {
				ao.FindOrAddAdjacentSID(sd.Owner, o).EdgeTo(o, activedirectory.EdgeOwns)
			}
		}
	}, "Indicator that someone owns an object", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.Type() == engine.ObjectTypeForeignSecurityPrincipal {
				continue
			}

			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_GENERIC_ALL, engine.NullGUID, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeGenericAll)
				}
			}
		}
	}, "Indicator that someone has full permissions on an object", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.Type() == engine.ObjectTypeForeignSecurityPrincipal {
				continue
			}

			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_GENERIC_WRITE, engine.NullGUID, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeWriteAll)
				}
			}
		}
	}, "Indicator that someone can write to all attributes and do all validated writes on an object", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.Type() == engine.ObjectTypeForeignSecurityPrincipal {
				continue
			}

			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_WRITE_PROPERTY, engine.NullGUID, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeWritePropertyAll)
				}
			}
		}
	}, "Indicator that someone can write to all attributes of an object", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.Type() == engine.ObjectTypeForeignSecurityPrincipal {
				continue
			}

			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_WRITE_PROPERTY_EXTENDED, engine.NullGUID, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeWriteExtendedAll)
				}
			}
		}
	}, "Indicator that someone do all validated writes on an object", engine.BeforeMergeFinal)

	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe IMPORTANT
	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.Type() == engine.ObjectTypeForeignSecurityPrincipal {
				continue
			}

			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_WRITE_OWNER, engine.NullGUID, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeTakeOwnership)
				}
			}
		}
	}, "Indicator that someone is allowed to take ownership of an object", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.Type() == engine.ObjectTypeForeignSecurityPrincipal {
				continue
			}

			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_WRITE_DACL, engine.NullGUID, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeWriteDACL)
				}
			}
		}
	}, "Indicator that someone can change permissions on an object", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			sd, err := o.SecurityDescriptor()
			if o.Type() != engine.ObjectTypeAttributeSchema {
				continue
			}
			// FIXME - check for SYSTEM ATTRIBUTES - these can NEVER be changed
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeSecurityGUIDGUID, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeWriteAttributeSecurityGUID) // Experimental, I've never run into this misconfiguration
				}
			}
		}
	}, `Allows an attacker to modify the attribute security set of an attribute, promoting it to a weaker attribute set (experimental/wrong)`, engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// Only users, computers and service accounts
			if o.Type() != engine.ObjectTypeUser && o.Type() != engine.ObjectTypeComputer {
				continue
			}
			// Check who can reset the password
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_CONTROL_ACCESS, ResetPwd, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeResetPassword)
				}
			}
		}
	}, "Indicator that a group or user can reset the password of an account", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// Only managed service accounts
			if o.Type() != engine.ObjectTypeManagedServiceAccount && o.Type() != engine.ObjectTypeGroupManagedServiceAccount {
				continue
			}

			// Check who can reset the password
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_READ_PROPERTY, AttributeMSDSManagedPasswordId, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeReadPasswordId)
				}
			}
		}
	}, "Indicator that a group or user can read the msDS-ManagedPasswordId for use in MGSA Golden attack", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		authusers := FindWellKnown(ao, windowssecurity.AuthenticatedUsersSID)
		if authusers == nil {
			ui.Error().Msgf("Could not locate Authenticated Users")
			return
		}

		for _, o := range ao.Slice() {
			// Only computers and users
			if o.Type() != engine.ObjectTypeUser {
				continue
			}
			if o.Attr(activedirectory.ServicePrincipalName).Len() > 0 {
				o.SetValues(engine.MetaHasSPN, engine.AttributeValueInt(1))

				authusers.EdgeTo(o, activedirectory.EdgeHasSPN)
			}
		}
	}, "Indicator that a user has a ServicePrincipalName and an authenticated user can Kerberoast it", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		everyone := FindWellKnown(ao, windowssecurity.EveryoneSID)
		if everyone == nil {
			ui.Error().Msgf("Could not locate Everyone")
			return
		}

		for _, o := range ao.Slice() {
			// Only users
			if o.Type() != engine.ObjectTypeUser {
				continue
			}
			if uac, ok := o.AttrInt(activedirectory.UserAccountControl); ok && uac&engine.UAC_DONT_REQ_PREAUTH != 0 {
				everyone.EdgeTo(o, activedirectory.EdgeDontReqPreauth)
			}
		}
	}, "Indicator that a user has \"don't require preauth\" and can be kerberoasted", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// Only computers and users
			if o.Type() != engine.ObjectTypeUser {
				continue
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_WRITE_PROPERTY, ValidateWriteSPN, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeWriteSPN)
				}
			}
		}
	}, "Indicator that a user can change the ServicePrincipalName attribute, and then Kerberoast the account", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// Only computers and users
			if o.Type() != engine.ObjectTypeUser {
				continue
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_WRITE_PROPERTY_EXTENDED, ValidateWriteSPN, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeWriteValidatedSPN)
				}
			}
		}
	}, "Indicator that a user can change the ServicePrincipalName attribute (validate write), and then Kerberoast the account", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// Only computers
			if o.Type() != engine.ObjectTypeComputer {
				continue
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeAllowedToActOnBehalfOfOtherIdentity, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeWriteAllowedToAct) // Success rate?
				}
			}
		}
	}, `Modify the msDS-AllowedToActOnBehalfOfOtherIdentity on a computer to enable any SPN enabled user to impersonate anyone else`, engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// Only for groups
			if o.Type() != engine.ObjectTypeGroup {
				continue
			}
			// It's a group
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeMember, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeAddMember)
				}
			}
		}
	}, "Permission to add a member to a group", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// Only for groups
			if o.Type() != engine.ObjectTypeGroup {
				continue
			}
			// It's a group
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeSetGroupMembership, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeAddMemberGroupAttr)
				}
			}
		}
	}, "Permission to add a member to a group (via attribute set)", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// Only for groups
			if o.Type() != engine.ObjectTypeGroup {
				continue
			}
			// It's a group
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_WRITE_PROPERTY_EXTENDED, ValidateWriteSelfMembership, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeAddSelfMember)
				}
			}
		}
	}, "Permission to add yourself to a group", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			o.Attr(activedirectory.MSDSGroupMSAMembership).Iterate(func(msads engine.AttributeValue) bool {
				sd, err := engine.ParseSecurityDescriptor([]byte(msads.String()))
				if err == nil {
					for _, acl := range sd.DACL.Entries {
						if acl.Type == engine.ACETYPE_ACCESS_ALLOWED {
							ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeReadMSAPassword)
						}
					}
				}
				return true
			})
		}
	}, "Allows someone to read a password of a managed service account", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// Only for users
			if o.Type() != engine.ObjectTypeUser {
				continue
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeAltSecurityIdentitiesGUID, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeWriteAltSecurityIdentities)
				}
			}
		}
	}, "Allows an attacker to define a certificate that can be used to authenticate as the user", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// Only for users
			if o.Type() != engine.ObjectTypeUser {
				continue
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeProfilePathGUID, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeWriteProfilePath)
				}
			}
		}
	}, "Change user profile path (allows an attacker to trigger a user auth against an attacker controlled UNC path)", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// Only for users
			if o.Type() != engine.ObjectTypeUser {
				continue
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeScriptPathGUID, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeWriteScriptPath)
				}
			}
		}
	}, "Change user script path (allows an attacker to trigger a user auth against an attacker controlled UNC path)", engine.BeforeMergeFinal)
	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			msas := o.Attr(activedirectory.MSDSHostServiceAccount).Slice()
			for _, dn := range msas {
				if targetmsa, found := ao.Find(engine.DistinguishedName, dn); found {
					o.EdgeTo(targetmsa, activedirectory.EdgeHasMSA)
				}
			}
		}
	}, "Indicates that the object has a service account in use", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// Only for groups
			if o.Type() != engine.ObjectTypeUser && o.Type() != engine.ObjectTypeComputer {
				continue
			}
			// It's a group
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_WRITE_PROPERTY, AttributeMSDSKeyCredentialLink, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeWriteKeyCredentialLink)
				}
			}
		}
	}, "Allows you to write your own cert to keyCredentialLink, and then auth as that user (no password reset needed)", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			sids := o.Attr(activedirectory.SIDHistory).Slice()
			for _, sidval := range sids {
				if sid, ok := sidval.Raw().(windowssecurity.SID); ok {
					target := ao.FindOrAddAdjacentSID(sid, o)
					o.EdgeTo(target, activedirectory.EdgeSIDHistoryEquality)
				}
			}
		}
	}, "Indicates that object has a SID History attribute pointing to the other object, making them the 'same' permission wise", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.Type() == engine.ObjectTypeForeignSecurityPrincipal {
				continue
			}

			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_CONTROL_ACCESS, engine.NullGUID, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeAllExtendedRights)
				}
			}
		}
	}, "Indicates that you have all extended rights", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.Type() != engine.ObjectTypePKIEnrollmentService {
				continue
			}
			for _, cts := range o.AttrString(engine.A("certificateTemplates")) {
				for _, ct := range cts {
					templates, _ := ao.FindMulti(engine.Name, engine.AttributeValueString(ct))
					for _, template := range templates {
						if template.Type() == engine.ObjectTypeCertificateTemplate {
							o.EdgeTo(template, EdgePublishesCertificateTemplate)
						}
					}
				}
			}
		}
	}, "Certificate service publishes Certificate Template", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.Type() != engine.ObjectTypeCertificateTemplate {
				continue
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/211ab1e3-bad6-416d-9d56-8480b42617a4
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_CONTROL_ACCESS, ExtendedRightCertificateEnroll, ao) ||
					sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_VOODOO_BIT, uuid.Nil, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeCertificateEnroll)
				}
			}
		}
	}, "Permission to enroll into a certificate template", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.Type() != engine.ObjectTypeCertificateTemplate {
				continue
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/211ab1e3-bad6-416d-9d56-8480b42617a4
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_CONTROL_ACCESS, ExtendedRightCertificateAutoEnroll, ao) ||
					sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_VOODOO_BIT, uuid.Nil, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeCertificateAutoEnroll)
				}
			}
		}
	}, "Permission to auto-enroll into a certificate template", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_VOODOO_BIT, uuid.Nil, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeVoodooBit)
				}
			}
		}
	}, "Has the Voodoo Bit set", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.Type() != engine.ObjectTypeDomainDNS {
				continue
			}
			if !o.HasAttr(activedirectory.SystemFlags) {
				continue
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				continue
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationSyncronize, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeDSReplicationSyncronize)
				}
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChanges, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeDSReplicationGetChanges)
				}
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChangesAll, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeDSReplicationGetChangesAll)
				}
				if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChangesInFilteredSet, ao) {
					ao.FindOrAddAdjacentSID(acl.SID, o).EdgeTo(o, activedirectory.EdgeDSReplicationGetChangesInFilteredSet)
				}
			}

			// Add the DCsync combination flag
			o.EdgeIterator(engine.In, func(target *engine.Object, edge engine.EdgeBitmap) bool {
				if edge.IsSet(activedirectory.EdgeDSReplicationGetChanges) && edge.IsSet(activedirectory.EdgeDSReplicationGetChangesAll) {
					// DCsync attack WOT WOT
					target.EdgeTo(o, activedirectory.EdgeDCsync)
				}
				return true
			})
		}
	}, "Permissions on DomainDNS objects leading to DCsync attacks", engine.BeforeMergeFinal)

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Ensure everyone has a family
		for _, computeraccount := range ao.Slice() {
			if computeraccount.Type() != engine.ObjectTypeComputer {
				continue
			}

			sid := computeraccount.OneAttr(engine.ObjectSid)
			if sid == nil {
				ui.Error().Msgf("Computer account without SID: %v", computeraccount.DN())
				continue
			}
			machine, _ := ao.FindOrAdd(
				DomainJoinedSID, sid,
				engine.IgnoreBlanks,
				engine.Name, computeraccount.Attr(engine.Name),
				activedirectory.ObjectCategorySimple, "Machine",
				DnsHostName, computeraccount.Attr(DnsHostName),
			)
			// ui.Debug().Msgf("Added machine for SID %v", sid.String())

			machine.EdgeTo(computeraccount, EdgeAuthenticatesAs)
			machine.EdgeTo(computeraccount, EdgeMachineAccount)
			machine.ChildOf(computeraccount)
		}
	},
		"creating Machine objects (representing the machine running the OS)",
		engine.BeforeMerge)

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Ensure everyone has a family
		for _, o := range ao.Slice() {

			if o.Parent() != nil {
				continue
			}

			if o == ao.Root() {
				continue
			}

			if parent, found := ao.DistinguishedParent(o); found {
				o.ChildOf(parent)
			} else {
				dn := o.DN()
				if o.Type() == engine.ObjectTypeDomainDNS && len(dn) > 3 && strings.EqualFold("dc=", dn[:3]) {
					// Top of some AD we think, hook to top of browsable tree
					o.ChildOf(ao.Root())
					continue
				}
				ui.Debug().Msgf("AD object %v (%v) has no parent :-(", o.Label(), o.DN())
			}
		}
	},
		"applying parent/child relationships",
		engine.BeforeMergeHigh)

	Loader.AddProcessor(func(ao *engine.Objects) {
		type domaininfo struct {
			suffix string
			name   string
		}
		var domains []domaininfo

		results, found := ao.FindMulti(engine.ObjectClass, engine.AttributeValueString("crossRef"))

		if !found {
			ui.Error().Msg("No domainDNS object found, can't apply DownLevelLogonName to objects")
			return
		}

		for _, o := range results {
			// Store domain -> netbios name in array for later
			dn := o.OneAttrString(NCName)
			netbiosname := o.OneAttrString(NetBIOSName)

			if dn == "" || netbiosname == "" {
				// Some crossref objects have no NCName or NetBIOSName, skip them
				continue
			}

			domains = append(domains, domaininfo{
				suffix: dn,
				name:   netbiosname,
			})
		}

		if len(domains) == 0 {
			ui.Error().Msg("No NCName to NetBIOSName mapping found, can't apply DownLevelLogonName to objects")
			return
		}

		// Sort the domains so we match on longest first
		sort.Slice(domains, func(i, j int) bool {
			// Less is More - so we sort in reverse order
			return len(domains[i].suffix) > len(domains[j].suffix)
		})

		// Apply DownLevelLogonName to relevant objects
		for _, o := range ao.Slice() {
			if !o.HasAttr(engine.SAMAccountName) {
				continue
			}
			dn := o.DN()
			for _, domaininfo := range domains {
				if strings.HasSuffix(dn, domaininfo.suffix) {
					o.SetValues(engine.DownLevelLogonName, engine.AttributeValueString(domaininfo.name+"\\"+o.OneAttrString(engine.SAMAccountName)))
					break
				}
			}
		}

		ao.DropIndex(engine.DownLevelLogonName)
	},
		"applying DownLevelLogonName attribute",
		engine.BeforeMergeLow)

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Add domain part attribute from distinguished name to objects
		for _, o := range ao.Slice() {
			// Only objects with a DistinguishedName
			if o.DN() == "" {
				continue
			}

			if o.HasAttr(engine.DomainContext) {
				continue
			}

			parts := strings.Split(o.DN(), ",")
			lastpart := -1

			for i := len(parts) - 1; i >= 0; i-- {
				part := parts[i]
				if len(part) < 3 || !strings.EqualFold("dc=", part[:3]) {
					break
				}
				if strings.EqualFold("DC=ForestDNSZones", part) || strings.EqualFold("DC=DomainDNSZones", part) {
					break
				}
				lastpart = i
			}

			if lastpart != -1 {
				o.SetValues(engine.DomainContext, engine.AttributeValueString(strings.Join(parts[lastpart:], ",")))
			}
		}
	},
		"applying domain part attribute",
		engine.BeforeMergeLow)

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Find all the AdminSDHolder containers
		for _, adminsdholder := range ao.Filter(func(o *engine.Object) bool {
			return strings.HasPrefix(o.OneAttrString(engine.DistinguishedName), "CN=AdminSDHolder,CN=System,")
		}).Slice() {
			// We found it - so we know it can change ACLs of some objects
			domaincontext := adminsdholder.OneAttrString(engine.DomainContext)

			// Are some groups excluded?
			excluded_mask := 0

			// Find dsHeuristics, this defines groups EXCLUDED From AdminSDHolder application
			// https://social.technet.microsoft.com/wiki/contents/articles/22331.adminsdholder-protected-groups-and-security-descriptor-propagator.aspx#What_is_a_protected_group
			if ds, found := ao.Find(engine.DistinguishedName, engine.AttributeValueString("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,"+domaincontext)); found {
				excluded := ds.OneAttrString(activedirectory.DsHeuristics)
				if len(excluded) >= 16 {
					excluded_mask = strings.Index("0123456789ABCDEF", strings.ToUpper(string(excluded[15])))
				}
			}

			for _, o := range ao.Filter(func(o *engine.Object) bool {
				// Check if object is a group
				if o.Type() != engine.ObjectTypeGroup {
					return false
				}

				// Only this "local" AD (for multi domain analysis)
				if o.OneAttrString(engine.DomainContext) != domaincontext {
					return false
				}
				return true
			}).Slice() {

				grpsid := o.SID()
				if grpsid.IsNull() {
					continue
				}

				switch grpsid.RID() {
				case DOMAIN_USER_RID_ADMIN:
				case DOMAIN_USER_RID_KRBTGT:
				case DOMAIN_GROUP_RID_ADMINS:
				case DOMAIN_GROUP_RID_CONTROLLERS:
				case DOMAIN_GROUP_RID_SCHEMA_ADMINS:
				case DOMAIN_GROUP_RID_ENTERPRISE_ADMINS:
				case DOMAIN_GROUP_RID_READONLY_CONTROLLERS:
				case DOMAIN_ALIAS_RID_ADMINS:
				case DOMAIN_ALIAS_RID_ACCOUNT_OPS:
					if excluded_mask&1 != 0 {
						continue
					}
				case DOMAIN_ALIAS_RID_SYSTEM_OPS:
					if excluded_mask&2 != 0 {
						continue
					}
				case DOMAIN_ALIAS_RID_PRINT_OPS:
					if excluded_mask&4 != 0 {
						continue
					}
				case DOMAIN_ALIAS_RID_BACKUP_OPS:
					if excluded_mask&8 != 0 {
						continue
					}
				case DOMAIN_ALIAS_RID_REPLICATOR:
				default:
					// Not a protected group
					continue
				}

				// Only domain groups
				if grpsid.Component(2) != 21 && grpsid.Component(2) != 32 {
					ui.Debug().Msgf("RID match but not domain object for %v with SID %v", o.OneAttrString(engine.DistinguishedName), o.SID().String())
					continue
				}

				// Apply this edge
				adminsdholder.EdgeTo(o, activedirectory.EdgeOverwritesACL)
				ApplyToGroupMembers(o, func(target *engine.Object) {
					adminsdholder.EdgeTo(target, activedirectory.EdgeOverwritesACL)
				}, true)
			}
		}
	},
		"AdminSDHolder rights propagation indicator",
		engine.BeforeMerge)

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Add our known SIDs if they're missing
		for sid, name := range windowssecurity.KnownSIDs {
			binsid, err := windowssecurity.ParseStringSID(sid)
			if err != nil {
				ui.Fatal().Msgf("Problem parsing SID %v", sid)
			}
			if fo := FindWellKnown(ao, binsid); fo == nil {
				dn := "CN=" + name + ",CN=microsoft-builtin"
				ui.Debug().Msgf("Adding missing well known SID %v (%v) as %v", name, sid, dn)
				ao.Add(engine.NewObject(
					engine.DistinguishedName, engine.AttributeValueString(dn),
					engine.Name, engine.AttributeValueString(name),
					engine.ObjectSid, engine.AttributeValueSID(binsid),
					engine.ObjectClass, engine.AttributeValueString("person"), engine.AttributeValueString("user"), engine.AttributeValueString("top"),
					engine.ObjectCategorySimple, engine.AttributeValueString("Group"),
				))
			}
		}
	},
		"missing well-known SIDs",
		engine.BeforeMergeLow,
	)

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Generate member of chains
		everyonesid, _ := windowssecurity.ParseStringSID("S-1-1-0")
		everyone := FindWellKnown(ao, everyonesid)
		if everyone == nil {
			ui.Fatal().Msgf("Could not locate Everyone, aborting - this should at least have been added during earlier preprocessing")
		}

		authenticateduserssid, _ := windowssecurity.ParseStringSID("S-1-5-11")
		authenticatedusers := FindWellKnown(ao, authenticateduserssid)
		if authenticatedusers == nil {
			ui.Fatal().Msgf("Could not locate Authenticated Users, aborting - this should at least have been added during earlier preprocessing")
		}

		ncname, netbiosname, dnsroot, domainsid, err := FindDomain(ao)
		if err != nil {
			ui.Fatal().Msgf("Could not get needed domain information (%v), aborting", err)
		}

		dnsroot = strings.ToLower(dnsroot)
		TrustMap.Store(TrustPair{
			SourceNCName:  ncname,
			SourceDNSRoot: dnsroot,
			SourceNetbios: netbiosname,
			SourceSID:     domainsid.String(),
		}, TrustInfo{})

		for _, object := range ao.Slice() {
			if rid, ok := object.AttrInt(activedirectory.PrimaryGroupID); ok {
				sid := object.SID()
				if len(sid) > 8 {
					sidbytes := []byte(sid)
					binary.LittleEndian.PutUint32(sidbytes[len(sid)-4:], uint32(rid))
					primarygroup := ao.FindOrAddAdjacentSID(windowssecurity.SID(sidbytes), object)
					object.EdgeTo(primarygroup, activedirectory.EdgeMemberOfGroup)
				}
			}

			// Crude special handling for Everyone and Authenticated Users
			if object.Type() == engine.ObjectTypeUser || object.Type() == engine.ObjectTypeComputer || object.Type() == engine.ObjectTypeManagedServiceAccount || object.Type() == engine.ObjectTypeForeignSecurityPrincipal || object.Type() == engine.ObjectTypeGroupManagedServiceAccount {
				object.EdgeTo(authenticatedusers, activedirectory.EdgeMemberOfGroup)
			}
			authenticatedusers.EdgeTo(everyone, activedirectory.EdgeMemberOfGroup)

			if lastlogon, ok := object.AttrTime(activedirectory.LastLogonTimestamp); ok {
				object.SetValues(engine.MetaLastLoginAge, engine.AttributeValueInt(int(time.Since(lastlogon)/time.Hour)))
			}
			if passwordlastset, ok := object.AttrTime(activedirectory.PwdLastSet); ok {
				object.SetValues(engine.MetaPasswordAge, engine.AttributeValueInt(int(time.Since(passwordlastset)/time.Hour)))
			}
			if strings.Contains(strings.ToLower(object.OneAttrString(activedirectory.OperatingSystem)), "linux") {
				object.SetValues(engine.MetaLinux, engine.AttributeValueInt(1))
			}
			if strings.Contains(strings.ToLower(object.OneAttrString(activedirectory.OperatingSystem)), "windows") {
				object.SetValues(engine.MetaWindows, engine.AttributeValueInt(1))
			}
			if object.Attr(activedirectory.MSmcsAdmPwdExpirationTime).Len() > 0 {
				object.SetValues(engine.MetaLAPSInstalled, engine.AttributeValueInt(1))
			}
			if uac, ok := object.AttrInt(activedirectory.UserAccountControl); ok {
				if uac&engine.UAC_TRUSTED_FOR_DELEGATION != 0 && uac&engine.UAC_NOT_DELEGATED == 0 {
					object.SetValues(engine.MetaUnconstrainedDelegation, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_TRUSTED_TO_AUTH_FOR_DELEGATION != 0 {
					object.SetValues(engine.MetaConstrainedDelegation, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_NOT_DELEGATED != 0 {
					ui.Debug().Msgf("%v has can't be used as delegation", object.DN())
				}
				if uac&engine.UAC_WORKSTATION_TRUST_ACCOUNT != 0 {
					object.SetValues(engine.MetaWorkstation, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_SERVER_TRUST_ACCOUNT != 0 {
					object.SetValues(engine.MetaServer, engine.AttributeValueInt(1))

					// All DCs are members of Enterprise Domain Controllers
					object.EdgeTo(ao.FindOrAddAdjacentSID(EnterpriseDomainControllers, object), activedirectory.EdgeMemberOfGroup)

					// Also they can DCsync because of this membership ... FIXME
				}
				if uac&engine.UAC_ACCOUNTDISABLE != 0 {
					object.SetValues(engine.MetaAccountDisabled, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_PASSWD_CANT_CHANGE != 0 {
					object.SetValues(engine.MetaPasswordCantChange, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_DONT_EXPIRE_PASSWORD != 0 {
					object.SetValues(engine.MetaPasswordNoExpire, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_PASSWD_NOTREQD != 0 {
					object.SetValues(engine.MetaPasswordNotRequired, engine.AttributeValueInt(1))
				}
				if uac&engine.UAC_SERVER_TRUST_ACCOUNT != 0 {
					// Domain Controller
					// find the machine object for this
					machine, found := ao.FindTwo(engine.ObjectCategorySimple, engine.AttributeValueString("Machine"),
						DomainJoinedSID, engine.AttributeValueSID(object.SID()))
					if !found {
						ui.Warn().Msgf("Can not find machine object for DC %v", object.DN())
					} else {
						domainContext := object.OneAttr(engine.DomainContext)
						if domainContext == nil {
							ui.Fatal().Msgf("DomainController %v has no DomainContext attribute", object.DN())
						}

						if administrators, found := ao.FindTwo(engine.ObjectSid, engine.AttributeValueSID(windowssecurity.AdministratorsSID),
							engine.DomainContext, domainContext); found {
							administrators.EdgeTo(machine, activedirectory.EdgeLocalAdminRights)
						} else {
							ui.Warn().Msgf("Could not find Administrators group for %v", object.DN())
						}

						if remotedesktopusers, found := ao.FindTwo(engine.ObjectSid, engine.AttributeValueSID(windowssecurity.RemoteDesktopUsersSID),
							engine.DomainContext, domainContext); found {
							remotedesktopusers.EdgeTo(machine, activedirectory.EdgeLocalRDPRights)
						} else {
							ui.Warn().Msgf("Could not find Remote Desktop Users group for %v", object.DN())
						}

						if distributeddcomusers, found := ao.FindTwo(engine.ObjectSid, engine.AttributeValueSID(windowssecurity.DCOMUsersSID),
							engine.DomainContext, domainContext); found {
							distributeddcomusers.EdgeTo(machine, activedirectory.EdgeLocalDCOMRights)
						} else {
							ui.Warn().Msgf("Could not find DCOM Users group for %v", object.DN())
						}
					}
				}
			}

			if object.Type() == engine.ObjectTypeTrust {
				// http://www.frickelsoft.net/blog/?p=211
				var direction string
				dir, _ := object.AttrInt(activedirectory.TrustDirection)
				switch dir {
				case 0:
					direction = "disabled"
				case 1:
					direction = "incoming"
				case 2:
					direction = "outgoing"
				case 3:
					direction = "bidirectional"
				}

				attr, _ := object.AttrInt(activedirectory.TrustAttributes)

				partner := object.OneAttrString(activedirectory.TrustPartner)

				ui.Info().Msgf("Domain %v has a %v trust with %v", dnsroot, direction, partner)

				if dir&2 != 0 && attr&0x08 != 0 && attr&0x40 != 0 {
					ui.Info().Msgf("SID filtering is not enabled, so pwn %v and pwn this AD too", object.OneAttr(activedirectory.TrustPartner))
				}

				TrustMap.Store(TrustPair{
					SourceDNSRoot: dnsroot,
					TargetDNSRoot: partner,
				}, TrustInfo{
					Direction: TrustDirection(dir),
				})
			}

			/* else if object.HasAttrValue(engine.ObjectClass, "classSchema") {
				if u, ok := object.OneAttrRaw(engine.SchemaIDGUID).(uuid.UUID); ok {
					// ui.Debug().Msgf("Adding schema class %v %v", u, object.OneAttr(Name))
					engine.AllSchemaClasses[u] = object
				}
			}*/
		}
	},
		"Active Directory objects and metadata",
		engine.BeforeMerge)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, object := range ao.Slice() {
			// We'll put the ObjectClass UUIDs in a synthetic attribute, so we can look it up later quickly (and without access to Objects)
			objectclasses := object.Attr(engine.ObjectClass)
			if objectclasses.Len() > 0 {
				guids := make([]engine.AttributeValue, 0, objectclasses.Len())
				objectclasses.Iterate(func(class engine.AttributeValue) bool {
					if oto, found := ao.Find(engine.LDAPDisplayName, class); found {
						if guid, ok := oto.OneAttr(activedirectory.SchemaIDGUID).(engine.AttributeValueGUID); !ok {
							ui.Debug().Msgf("%v", oto)
							ui.Fatal().Msgf("Could not translate SchemaIDGUID for class %v - I need a Schema to work properly", class)
						} else {
							guids = append(guids, guid)
						}
					} else {
						ui.Warn().Msgf("Could not resolve object class %v, perhaps you didn't get a dump of the schema?", class.String())
					}
					return true // continue
				})
				object.SetFlex(engine.ObjectClassGUIDs, guids)
			}

			// ObjectCategory handling
			var objectcategoryguid engine.AttributeValue
			var simple engine.AttributeValue

			objectcategoryguid = engine.AttributeValueGUID(engine.UnknownGUID)
			simple = engine.AttributeValueString("Unknown")

			typedn := object.OneAttr(engine.ObjectCategory)

			// Does it have one, and does it have a comma, then we're assuming it's not just something we invented
			if typedn != nil {
				if oto, found := ao.Find(engine.DistinguishedName, typedn); found {
					if _, ok := oto.OneAttrRaw(activedirectory.SchemaIDGUID).(uuid.UUID); ok {
						objectcategoryguid = oto.OneAttr(activedirectory.SchemaIDGUID)
						simple = oto.OneAttr(activedirectory.Name)
					} else {
						ui.Error().Msgf("Could not translate SchemaIDGUID for %v", typedn)
					}
				} else {
					ui.Error().Msgf("Could not resolve object category %v, perhaps you didn't get a dump of the schema?", typedn)
				}
			}

			object.SetFlex(
				engine.ObjectCategoryGUID, objectcategoryguid,
				engine.ObjectCategorySimple, simple,
			)
		}
	},
		"Set ObjectCategorySimple (for Type call) to Active Directory objects",
		engine.BeforeMergeLow,
	)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, object := range ao.Slice() {
			if object.HasAttrValue(engine.Name, engine.AttributeValueString("Protected Users")) && object.SID().RID() == 525 { // "Protected Users"
				ApplyToGroupMembers(object, func(member *engine.Object) {
					if member.Type() == engine.ObjectTypeComputer || member.Type() == engine.ObjectTypeUser {
						member.SetValues(engine.MetaProtectedUser, engine.AttributeValueInt(1))
					}
				}, true)
			}
		}
	},
		"Protected users meta attribute",
		engine.BeforeMerge,
	)

	Loader.AddProcessor(func(ao *engine.Objects) {
		// Find all the DomainDNS objects, and find the domain object
		domains := make(map[string]windowssecurity.SID)

		domaindnsobjects, found := ao.FindMulti(engine.ObjectClass, engine.AttributeValueString("domainDNS"))

		if !found {
			ui.Error().Msg("Could not find any domainDNS objects")
		}

		for _, domaindnsobject := range domaindnsobjects {
			domainSID, sidok := domaindnsobject.OneAttrRaw(activedirectory.ObjectSid).(windowssecurity.SID)
			dn := domaindnsobject.OneAttrString(activedirectory.DistinguishedName)
			if sidok {
				domains[dn] = domainSID
			}
		}

		for _, o := range ao.Slice() {
			if o.HasAttr(engine.ObjectSid) && o.SID().Component(2) == 21 && !o.HasAttr(engine.DistinguishedName) && o.HasAttr(engine.DomainContext) {
				// An unknown SID, is it ours or from another domain?
				ourDomainDN := o.OneAttrString(engine.DomainContext)
				ourDomainSid, domainfound := domains[ourDomainDN]
				if !domainfound {
					continue
				}

				if o.SID().StripRID() == ourDomainSid {
					ui.Debug().Msgf("Found a 'dangling' local SID object %v. This is either a SID from a deleted object (most likely) or hardened objects that are not readable with the account used to dump data.", o.SID())
				} else {
					ui.Debug().Msgf("Found a 'lost' foreign SID object %v, adding it as a synthetic Foreign-Security-Principal", o.SID())
					o.SetFlex(
						engine.DistinguishedName, engine.AttributeValueString(o.SID().String()+",CN=ForeignSecurityPrincipals,"+ourDomainDN),
						engine.ObjectCategorySimple, "Foreign-Security-Principal",
						engine.DataLoader, "Autogenerated",
					)
				}
			}
		}
	},
		"Creation of synthetic Foreign-Security-Principal objects",
		engine.AfterMergeLow)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, machine := range ao.Slice() {
			// Only for machines, you can't really pwn users this way
			if machine.Type() != ObjectTypeMachine {
				continue
			}

			// Find the computer AD object if any
			var computer *engine.Object
			machine.EdgeIterator(engine.Out, func(target *engine.Object, edge engine.EdgeBitmap) bool {
				if edge.IsSet(EdgeAuthenticatesAs) && target.Type() == engine.ObjectTypeComputer {
					computer = target
					return false //break
				}
				return true
			})

			if computer == nil {
				continue
			}

			// Find all perent containers with GP links
			var hasparent bool
			p := computer

			// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/5c7ecdad-469f-4b30-94b3-450b7fff868f
			allowEnforcedGPOsOnly := false
			for {
				newparent := p.Parent()
				var foundparent bool
				if newparent != nil && newparent.DN() != "" && strings.HasSuffix(p.DN(), newparent.DN()) {
					p = newparent
					foundparent = true
				}
				if !foundparent {
					// Fall back to old slow method of looking at DNs
					p, hasparent = ao.DistinguishedParent(p)
					if !hasparent {
						break
					}
				}

				var gpcachelinks engine.AttributeValues
				var found bool
				if gpcachelinks, found = p.Get(GPLinkCache); !found {
					// the hard way
					gpcachelinks = engine.NoValues{} // We assume there is nothing

					gplinks := strings.Trim(p.OneAttrString(activedirectory.GPLink), " ")
					if len(gplinks) != 0 {
						// ui.Debug().Msgf("GPlink for %v on container %v: %v", o.DN(), p.DN(), gplinks)
						if !strings.HasPrefix(gplinks, "[") || !strings.HasSuffix(gplinks, "]") {
							ui.Error().Msgf("Error parsing gplink on %v: %v", computer.DN(), gplinks)
						} else {
							links := strings.Split(gplinks[1:len(gplinks)-1], "][")

							var collecteddata engine.AttributeValueSlice
							for _, link := range links {
								linkinfo := strings.Split(link, ";")
								if len(linkinfo) != 2 {
									ui.Error().Msgf("Error parsing gplink on %v: %v", computer.DN(), gplinks)
									continue
								}
								linkedgpodn := linkinfo[0][7:] // strip LDAP:// prefix and link to this

								gpo, found := ao.Find(engine.DistinguishedName, engine.AttributeValueString(linkedgpodn))
								if !found {
									if _, warned := warnedgpos[linkedgpodn]; !warned {
										warnedgpos[linkedgpodn] = struct{}{}
										ui.Warn().Msgf("Object linked to GPO that is not found %v: %v", computer.DN(), linkedgpodn)
									}
								} else {
									linktype, _ := strconv.ParseInt(linkinfo[1], 10, 64)
									collecteddata = append(collecteddata, engine.AttributeValueObject{
										Object: gpo,
									}, engine.AttributeValueInt(linktype))
								}
							}
							gpcachelinks = collecteddata
						}
					}
					p.Set(GPLinkCache, gpcachelinks)
				}

				// cached or generated - pairwise pointer to gpo object and int
				gplinkslice := gpcachelinks.Slice()
				for i := 0; i < gpcachelinks.Len(); i += 2 {
					gpo := gplinkslice[i].Raw().(*engine.Object)
					gpLinkOptions := gplinkslice[i+1].Raw().(int64)
					// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/08090b22-bc16-49f4-8e10-f27a8fb16d18
					if gpLinkOptions&0x01 != 0 {
						// GPO link is disabled
						continue
					}
					if allowEnforcedGPOsOnly && gpLinkOptions&0x02 == 0 {
						// Enforcement required, but this is not an enforced GPO
						continue
					}
					gpo.EdgeTo(machine, activedirectory.EdgeAffectedByGPO)
				}

				gpoptions := p.OneAttrString(activedirectory.GPOptions)
				if gpoptions == "1" {
					// inheritance is blocked, so let's not forget that when moving up
					allowEnforcedGPOsOnly = true
				}
			}
		}
	},
		"Computers affected by a GPO",
		engine.AfterMergeLow,
	)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			if o.HasAttr(engine.ObjectSid) && !o.HasAttr(engine.DisplayName) {
				if name, found := windowssecurity.KnownSIDs[o.SID().String()]; found {
					o.SetFlex(engine.DisplayName, name)
				}
			}
		}
	},
		"Adding displayName to Well-Known SID objects that are missing them",
		engine.AfterMergeLow)

	// CREATOR_OWNER is a template for new objects, so this was totally wrong
	/*
		Loader.AddProcessor(func(ao *engine.Objects) {
			creatorowner, found := ao.Find(engine.ObjectSid, engine.AttributeValueSID(windowssecurity.CreatorOwnerSID))
			if !found {
				ui.Warn().Msg("Could not find Creator Owner Well Known SID. Not doing post-merge fixup")
				return
			}

			for target, edges := range creatorowner.CanPwn {
				// ACL grants CreatorOwnerSID something - so let's find the owner and give them the permissions
				if sd, err := target.SecurityDescriptor(); err == nil {
					if sd.Owner != windowssecurity.BlankSID {
						if realowners, found := ao.FindMulti(engine.ObjectSid, engine.AttributeValueSID(sd.Owner)); found {
							for _, realo := range realowners {
								if realo.Type() == engine.ObjectTypeForeignSecurityPrincipal || realo.Type() == engine.ObjectTypeOther {
									// Skip this
									continue
								}

								// Link real target
								realo.CanPwn[target] = realo.CanPwn[target].Merge(edges)
								target.PwnableBy[realo] = target.PwnableBy[realo].Merge(edges)

								// Unlink creatorowner
								delete(creatorowner.CanPwn, target)
								delete(target.PwnableBy, creatorowner)
							}
						}
					}
				}
			}
		},
			"CreatorOwnerSID resolution fixup",
			engine.BeforeMerge,
		)
	*/

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, object := range ao.Slice() {
			// Object that is member of something
			object.Attr(activedirectory.MemberOf).Iterate(func(memberof engine.AttributeValue) bool {
				group, found := ao.Find(engine.DistinguishedName, memberof)
				if !found {
					var sid engine.AttributeValueSID
					if stringsid, _, found := strings.Cut(memberof.String(), ",CN=ForeignSecurityPrincipals,"); found {
						// We can figure out what the SID is
						if c, err := windowssecurity.ParseStringSID(stringsid); err == nil {
							sid = engine.AttributeValueSID(c)
						}
						ui.Info().Msgf("Missing Foreign-Security-Principal: %v is a member of %v, which is not found - adding enhanced synthetic group", object.DN(), memberof)
					} else {
						ui.Warn().Msgf("Possible hardening? %v is a member of %v, which is not found - adding synthetic group. Your analysis will be degraded, try dumping with Domain Admin rights.", object.DN(), memberof)
					}
					group = engine.NewObject(
						engine.IgnoreBlanks,
						engine.DistinguishedName, memberof,
						engine.ObjectCategorySimple, engine.AttributeValueString("Group"),
						engine.ObjectClass, engine.AttributeValueString("top"), engine.AttributeValueString("group"),
						engine.Name, engine.AttributeValueString("Synthetic group "+memberof.String()),
						engine.Description, engine.AttributeValueString("Synthetic group"),
						engine.ObjectSid, sid,
						engine.DataLoader, engine.AttributeValueString("Autogenerated"),
					)
					ao.Add(group)
				}
				object.EdgeTo(group, activedirectory.EdgeMemberOfGroup)
				return true
			})

			// Group that contains members
			object.Attr(activedirectory.Member).Iterate(func(member engine.AttributeValue) bool {
				memberobject, found := ao.Find(engine.DistinguishedName, member)
				if !found {
					var sid engine.AttributeValueSID
					var category string
					if stringsid, _, found := strings.Cut(member.String(), ",CN=ForeignSecurityPrincipals,"); found {
						// We can figure out what the SID is
						if c, err := windowssecurity.ParseStringSID(stringsid); err == nil {
							sid = engine.AttributeValueSID(c)
							category = "Foreign-Security-Principal"
						}
						ui.Info().Msgf("Missing Foreign-Security-Principal: %v is a member of %v, which is not found - adding enhanced synthetic group", object.DN(), member)
					} else {
						ui.Warn().Msgf("Possible hardening? %v is a member of %v, which is not found - adding synthetic group. Your analysis will be degraded, try dumping with Domain Admin rights.", object.DN(), member)
					}
					memberobject = engine.NewObject(
						engine.IgnoreBlanks,
						engine.DistinguishedName, member,
						engine.ObjectCategorySimple, category,
						engine.ObjectSid, sid,
						engine.DataLoader, "Autogenerated",
					)
					ao.Add(memberobject)
				}
				memberobject.EdgeTo(object, activedirectory.EdgeMemberOfGroup)
				return true
			})
		}
	},
		"MemberOf and Member resolution",
		engine.AfterMergeLow,
	)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, o := range ao.Slice() {
			// Object that is member of something
			if o.Type() != engine.ObjectTypeGroup {
				continue
			}

			ApplyToGroupMembers(o, func(member *engine.Object) {
				if member.Type() != engine.ObjectTypeGroup && member.Type() != engine.ObjectTypeForeignSecurityPrincipal {
					member.EdgeTo(o, activedirectory.EdgeMemberOfGroupIndirect)
				}
			}, true)
		}
	},
		"MemberOfIndirect resolution",
		engine.AfterMerge,
	)

	Loader.AddProcessor(func(ao *engine.Objects) {
		for _, foreign := range ao.Filter(func(o *engine.Object) bool {
			return o.Type() == engine.ObjectTypeForeignSecurityPrincipal
		}).Slice() {
			sid := foreign.SID()
			if sid.IsNull() {
				ui.Error().Msgf("Found a foreign security principal with no SID %v", foreign.Label())
				continue
			}
			if sid.Component(2) == 21 {
				if sources, found := ao.FindMulti(engine.ObjectSid, engine.AttributeValueSID(sid)); found {
					for _, source := range sources {
						if source.Type() != engine.ObjectTypeForeignSecurityPrincipal {
							source.EdgeToEx(foreign, activedirectory.EdgeForeignIdentity, true)
						}
					}
				}
			} else {
				ui.Warn().Msgf("Found a foreign security principal %v with an non type 21 SID %v", foreign.DN(), sid.String())
			}
		}
	}, "Link foreign security principals to their native objects",
		engine.AfterMerge,
	)

	Loader.AddProcessor(func(ao *engine.Objects) {
		var warnlines int
		for _, gpo := range ao.Filter(func(o *engine.Object) bool {
			return o.Type() == engine.ObjectTypeGroupPolicyContainer
		}).Slice() {
			gpo.EdgeIterator(engine.In, func(group *engine.Object, methods engine.EdgeBitmap) bool {
				groupname := group.OneAttrString(engine.SAMAccountName)
				if strings.Contains(groupname, "%") {
					// Lowercase for ease
					groupname := strings.ToLower(groupname)

					// It has some sort of % variable in it, let's go
					gpo.EdgeIterator(engine.Out, func(affected *engine.Object, amethods engine.EdgeBitmap) bool {
						if amethods.IsSet(activedirectory.EdgeAffectedByGPO) && affected.Type() == engine.ObjectTypeComputer {
							netbiosdomain, computername, found := strings.Cut(affected.OneAttrString(engine.DownLevelLogonName), "\\")
							if !found {
								ui.Error().Msgf("Could not parse downlevel logon name %v", affected.OneAttrString(engine.DownLevelLogonName))
								return true //continue
							}
							computername = strings.TrimRight(computername, "$")

							realgroup := groupname
							realgroup = strings.Replace(realgroup, "%computername%", computername, -1)
							realgroup = strings.Replace(realgroup, "%domainname%", netbiosdomain, -1)
							realgroup = strings.Replace(realgroup, "%domain%", netbiosdomain, -1)

							var targetgroups []*engine.Object

							if !strings.Contains(realgroup, "\\") {
								realgroup = netbiosdomain + "\\" + realgroup
							}
							targetgroups, _ = ao.FindMulti(
								engine.DownLevelLogonName, engine.AttributeValueString(realgroup),
							)

							if len(targetgroups) == 0 {
								if warnlines < 10 {
									ui.Warn().Msgf("Could not find group %v", realgroup)
								}
								warnlines++
							} else if len(targetgroups) == 1 {
								for _, edge := range methods.Edges() {
									targetgroups[0].EdgeToEx(affected, edge, true)
								}
							} else {
								ui.Warn().Msgf("Found multiple groups for %v: %v", realgroup, targetgroups)
								for _, targetgroup := range targetgroups {
									ui.Warn().Msgf("Target: %v", targetgroup.DN())
								}
							}
						}
						return true
					})
				}
				return true
			})
		}
		if warnlines > 0 {
			ui.Warn().Msgf("%v groups could not be resolved, this could affect analysis results", warnlines)
		}

	}, "Resolve expanding group names to real names from GPOs",
		engine.AfterMerge,
	)
}

func ApplyToGroupMembers(startGroup *engine.Object, af func(member *engine.Object), recursive bool) {
	if recursive {
		applyToGroupMemberRecursive(startGroup, af, make(map[*engine.Object]struct{}))
		return
	}

	startGroup.EdgeIterator(engine.In, func(nextTarget *engine.Object, edge engine.EdgeBitmap) bool {
		if edge.IsSet(activedirectory.EdgeMemberOfGroup) {
			af(nextTarget)
		}
		return true
	})
}

func applyToGroupMemberRecursive(group *engine.Object, af func(nextTarget *engine.Object), appliedTo map[*engine.Object]struct{}) {
	group.EdgeIterator(engine.In, func(target *engine.Object, edge engine.EdgeBitmap) bool {
		if edge.IsSet(activedirectory.EdgeMemberOfGroup) || edge.IsSet(activedirectory.EdgeForeignIdentity) {
			if _, found := appliedTo[target]; !found {
				af(target)
				appliedTo[target] = struct{}{}
				applyToGroupMemberRecursive(target, af, appliedTo)
			}
		}
		return true
	})
}
