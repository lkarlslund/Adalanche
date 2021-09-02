package main

import (
	"fmt"
	"strings"

	"github.com/go-ini/ini"
	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/text/encoding/unicode"
)

// Enumer package from here:
// go get github.com/dmarkham/enumer

//go:generate enumer -type=PwnMethod -trimprefix=Pwn -json

// PwnAnalyzer takes an Object, examines it an outputs a list of Objects that can Pwn it
type PwnAnalyzer struct {
	Method         PwnMethod
	Description    string
	ObjectAnalyzer func(o *Object) []*Object
}

type PwnInfo struct {
	Target *Object
	Method PwnMethod
}

func (pm PwnMethod) Set(method PwnMethod) PwnMethod {
	return pm | method
}

type PwnSet map[*Object]PwnMethod

func (ps PwnSet) Set(o *Object, method PwnMethod) {
	// See if object is in the list
	ps[o] = ps[o].Set(method)
}

// Interesting permissions on AD
var (
	ResetPwd                   = uuid.UUID{0x00, 0x29, 0x95, 0x70, 0x24, 0x6d, 0x11, 0xd0, 0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e, 0x05, 0x29}
	DSReplicationGetChanges    = uuid.UUID{0x11, 0x31, 0xf6, 0xaa, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	DSReplicationGetChangesAll = uuid.UUID{0x11, 0x31, 0xf6, 0xad, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	DSReplicationSyncronize    = uuid.UUID{0x11, 0x31, 0xf6, 0xab, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}

	AttributeMember                                 = uuid.UUID{0xbf, 0x96, 0x79, 0xc0, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	AttributeSetGroupMembership                     = uuid.UUID{0xBC, 0x0A, 0xC2, 0x40, 0x79, 0xA9, 0x11, 0xD0, 0x90, 0x20, 0x00, 0xC0, 0x4F, 0xC2, 0xD4, 0xCF}
	AttributeSIDHistory                             = uuid.UUID{0x17, 0xeb, 0x42, 0x78, 0xd1, 0x67, 0x11, 0xd0, 0xb0, 0x02, 0x00, 0x00, 0xf8, 0x03, 0x67, 0xc1}
	AttributeAllowedToActOnBehalfOfOtherIdentity, _ = uuid.FromString("{3F78C3E5-F79A-46BD-A0B8-9D18116DDC79}")
	AttributeMSDSGroupMSAMembership                 = uuid.UUID{0x88, 0x8e, 0xed, 0xd6, 0xce, 0x04, 0xdf, 0x40, 0xb4, 0x62, 0xb8, 0xa5, 0x0e, 0x41, 0xba, 0x38}
	AttributeGPLink, _                              = uuid.FromString("{F30E3BBE-9FF0-11D1-B603-0000F80367C1}")
	AttributeMSDSKeyCredentialLink, _               = uuid.FromString("{5B47D60F-6090-40B2-9F37-2A4DE88F3063}")
	AttributeSecurityGUIDGUID, _                    = uuid.FromString("{bf967924-0de6-11d0-a285-00aa003049e2}")
	AttributeAltSecurityIdentitiesGUID, _           = uuid.FromString("{00FBF30C-91FE-11D1-AEBC-0000F80367C1}")
	AttributeProfilePathGUID, _                     = uuid.FromString("{bf967a05-0de6-11d0-a285-00aa003049e2}")
	AttributeScriptPathGUID, _                      = uuid.FromString("{bf9679a8-0de6-11d0-a285-00aa003049e2}")

	ExtendedRightCertificateEnroll, _ = uuid.FromString("0e10c968-78fb-11d2-90d4-00c04f79dc55")

	ValidateWriteSelfMembership, _ = uuid.FromString("bf9679c0-0de6-11d0-a285-00aa003049e2")
	ValidateWriteSPN, _            = uuid.FromString("f3a64788-5306-11d1-a9c5-0000f80367c1")

	ObjectGuidUser               = uuid.UUID{0xbf, 0x96, 0x7a, 0xba, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidComputer           = uuid.UUID{0xbf, 0x96, 0x7a, 0x86, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidGroup              = uuid.UUID{0xbf, 0x96, 0x7a, 0x9c, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidDomain             = uuid.UUID{0x19, 0x19, 0x5a, 0x5a, 0x6d, 0xa0, 0x11, 0xd0, 0xaf, 0xd3, 0x00, 0xc0, 0x4f, 0xd9, 0x30, 0xc9}
	ObjectGuidGPO                = uuid.UUID{0xf3, 0x0e, 0x3b, 0xc2, 0x9f, 0xf0, 0x11, 0xd1, 0xb6, 0x03, 0x00, 0x00, 0xf8, 0x03, 0x67, 0xc1}
	ObjectGuidOU                 = uuid.UUID{0xbf, 0x96, 0x7a, 0xa5, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidAttributeSchema, _ = uuid.FromString("{BF967A80-0DE6-11D0-A285-00AA003049E2}")

	NullGUID    = uuid.UUID{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	UnknownGUID = uuid.UUID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	OwnerSID, _        = SIDFromString("S-1-3-4")
	SystemSID, _       = SIDFromString("S-1-5-18")
	CreatorOwnerSID, _ = SIDFromString("S-1-3-0")
	SelfSID, _         = SIDFromString("S-1-5-10")

	AccountOperatorsSID, _          = SIDFromString("S-1-5-32-548")
	DAdministratorSID, _            = SIDFromString("S-1-5-21domain-500")
	DAdministratorsSID, _           = SIDFromString("S-1-5-32-544")
	BackupOperatorsSID, _           = SIDFromString("S-1-5-32-551")
	DomainAdminsSID, _              = SIDFromString("S-1-5-21domain-512")
	DomainControllersSID, _         = SIDFromString("S-1-5-21domain-516")
	EnterpriseAdminsSID, _          = SIDFromString("S-1-5-21root domain-519")
	KrbtgtSID, _                    = SIDFromString("S-1-5-21domain-502")
	PrintOperatorsSID, _            = SIDFromString("S-1-5-32-550")
	ReadOnlyDomainControllersSID, _ = SIDFromString("S-1-5-21domain-521")
	SchemaAdminsSID, _              = SIDFromString("S-1-5-21root domain-518")
	ServerOperatorsSID, _           = SIDFromString("S-1-5-32-549")
)

type PwnMethod uint64

const (
	_ PwnMethod = 1 << iota
	PwnCreateUser
	PwnCreateGroup
	PwnCreateComputer
	PwnCreateAnyObject
	PwnDeleteChildrenTarget
	PwnDeleteObject
	PwnInheritsSecurity
	PwnACLContainsDeny
	PwnResetPassword
	PwnOwns
	PwnGenericAll
	PwnWriteAll
	PwnWritePropertyAll
	PwnWriteExtendedAll
	PwnTakeOwnership
	PwnWriteDACL
	PwnWriteSPN
	PwnWriteValidatedSPN
	PwnWriteAllowedToAct
	PwnAddMember
	PwnAddMemberGroupAttr
	PwnAddSelfMember
	PwnReadMSAPassword
	PwnHasMSA
	PwnWriteKeyCredentialLink
	PwnWriteAttributeSecurityGUID
	PwnSIDHistoryEquality
	PwnAllExtendedRights
	PwnDCReplicationGetChanges
	PwnDCReplicationSyncronize
	PwnDSReplicationGetChangesAll
	PwnReadLAPSPassword
	PwnMemberOfGroup
	PwnHasSPN
	PwnHasSPNNoPreauth
	PwnAdminSDHolderOverwriteACL
	PwnComputerAffectedByGPO
	PwnGPOMachineConfigPartOfGPO
	PwnGPOUserConfigPartOfGPO
	PwnLocalAdminRights
	PwnLocalRDPRights
	PwnLocalDCOMRights
	PwnScheduledTaskOnUNCPath
	PwdMachineScript
	PwnWriteAltSecurityIdentities
	PwnWriteProfilePath
	PwnWriteScriptPath
	PwnCertificateEnroll

	PwnAllMethods uint64 = 1<<64 - 1
)

func (m PwnMethod) JoinedString() string {
	var result string
	for i := 0; i < 64; i++ {
		thismethod := PwnMethod(1 << i)
		if m&thismethod != 0 {
			if len(result) != 0 {
				result += ", "
			}
			result += thismethod.String()
		}
	}
	return result
}

func (m PwnMethod) StringSlice() []string {
	var result []string
	for i := 0; i < 64; i++ {
		thismethod := PwnMethod(1 << i)
		if m&thismethod != 0 {
			result = append(result, thismethod.String())
		}
	}
	return result
}

func (m PwnMethod) StringBoolMap() map[string]bool {
	var result = make(map[string]bool)
	for i := 0; i < 64; i++ {
		thismethod := PwnMethod(1 << i)
		if m&thismethod != 0 {
			result["pwn_"+thismethod.String()] = true
		}
	}
	return result
}

var PwnAnalyzers = []PwnAnalyzer{
	/* It's a Unicorn, dang ...
	{
		Method: "NullDACL",
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			if sd.Control&CONTROLFLAG_DACL_PRESENT != 0 || len(sd.DACL.Entries) == 0 {
				results = append(results, AllObjects.FindOrAddSID(acl.SID))
			}

			return results
		},
	}, */

	{
		Method: PwnComputerAffectedByGPO,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for computers, you can't really pwn users this way
			if o.Type() != ObjectTypeComputer {
				return results
			}
			// Find all perent containers with GP links
			var hasparent bool
			p := o
			for {
				gpoptions := p.OneAttr(GPOptions)
				if gpoptions == "1" {
					// inheritance is blocked, so don't move upwards
					break
				}

				p, hasparent = AllObjects.Parent(p)
				if !hasparent {
					break
				}

				gplinks := strings.Trim(p.OneAttr(GPLink), " ")
				if len(gplinks) == 0 {
					continue
				}
				// log.Debug().Msgf("GPlink for %v on container %v: %v", o.DN(), p.DN(), gplinks)
				if !strings.HasPrefix(gplinks, "[") || !strings.HasSuffix(gplinks, "]") {
					log.Error().Msgf("Error parsing gplink on %v: %v", o.DN(), gplinks)
					continue
				}
				links := strings.Split(gplinks[1:len(gplinks)-1], "][")
				for _, link := range links {
					linkinfo := strings.Split(link, ";")
					if len(linkinfo) != 2 {
						log.Error().Msgf("Error parsing gplink on %v: %v", o.DN(), gplinks)
						continue
					}
					linkedgpodn := linkinfo[0][7:] // strip LDAP:// prefix and link to this
					linktype := linkinfo[1]
					// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/08090b22-bc16-49f4-8e10-f27a8fb16d18
					if linktype == "1" || linktype == "3" {
						continue // Link is disabled
					}

					gpo, found := AllObjects.Find(linkedgpodn)
					if !found {
						log.Error().Msgf("Object linked to GPO that is not found %v: %v", o.DN(), linkedgpodn)
					} else {
						results = append(results, gpo)
					}
				}
			}
			return results
		},
	},

	{
		Method: PwnGPOMachineConfigPartOfGPO,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			if o.Type() != ObjectTypeContainer || o.OneAttr(Name) != "Machine" {
				return results
			}
			// Only for computers, you can't really pwn users this way
			p, hasparent := AllObjects.Parent(o)
			if !hasparent || p.Type() != ObjectTypeGroupPolicyContainer {
				if strings.Contains(p.DN(), "Policies") {
					log.Debug().Msgf("%v+", p)
				}
				return results
			}
			results = append(results, p)
			return results
		},
	},
	{
		Method: PwnGPOUserConfigPartOfGPO,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			if o.Type() != ObjectTypeContainer || o.OneAttr(Name) != "User" {
				return results
			}
			// Only for users, you can't really pwn users this way
			p, hasparent := AllObjects.Parent(o)
			if o.Type() != ObjectTypeContainer || !hasparent || p.Type() != ObjectTypeGroupPolicyContainer {
				return results
			}
			results = append(results, p)
			return results
		},
	},
	{
		Method: PwnCreateUser,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for containers and org units
			if o.Type() != ObjectTypeContainer && o.Type() != ObjectTypeOrganizationalUnit {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_CREATE_CHILD, ObjectGuidUser) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnCreateGroup,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for containers and org units
			if o.Type() != ObjectTypeContainer && o.Type() != ObjectTypeOrganizationalUnit {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_CREATE_CHILD, ObjectGuidGroup) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnCreateComputer,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for containers and org units
			if o.Type() != ObjectTypeContainer && o.Type() != ObjectTypeOrganizationalUnit {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_CREATE_CHILD, ObjectGuidComputer) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnCreateAnyObject,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for containers and org units
			if o.Type() != ObjectTypeContainer && o.Type() != ObjectTypeOrganizationalUnit {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_CREATE_CHILD, NullGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnDeleteObject,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for containers and org units
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DELETE, NullGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnDeleteChildrenTarget,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// If parent has DELETE CHILD, I can be deleted by some SID
			if parent, found := AllObjects.Find(o.ParentDN()); found {
				sd, err := parent.SecurityDescriptor()
				if err != nil {
					return results
				}
				for index, acl := range sd.DACL.Entries {
					if sd.DACL.AllowObjectClass(index, parent, RIGHT_DS_DELETE_CHILD, o.ObjectTypeGUID()) {
						results = append(results, AllObjects.FindOrAddSID(acl.SID))
					}
				}
			}
			return results
		},
	},
	{
		Method: PwnInheritsSecurity,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			if sd, err := o.SecurityDescriptor(); err == nil && sd.Control&CONTROLFLAG_DACL_PROTECTED == 0 {
				pdn := o.ParentDN()
				if pdn == o.DN() {
					// just to make sure we dont loop eternally by being stupid somehow
					return results
				}
				if parentobject, found := AllObjects.Find(pdn); found {
					results = append(results, parentobject)
				}
			}
			return results
		},
	},
	{
		Method: PwnMemberOfGroup,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for groups
			if o.Type() != ObjectTypeGroup && o.Type() != ObjectTypeForeignSecurityPrincipal {
				return results
			}
			// It's a group
			for _, member := range o.Members(false) {
				results = append(results, member)
			}
			return results
		},
	},
	{
		Method: PwnACLContainsDeny,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// It's a group
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for _, acl := range sd.DACL.Entries {
				if acl.Type == ACETYPE_ACCESS_DENIED || acl.Type == ACETYPE_ACCESS_DENIED_OBJECT {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnOwns,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			// https://www.alsid.com/crb_article/kerberos-delegation/
			// --- Citation bloc --- This is generally true, but an exception exists: positioning a Deny for the OWNER RIGHTS SID (S-1-3-4) in an object’s ACE removes the owner’s implicit control of this object’s DACL. ---------------------
			aclhasdeny := false
			for _, ace := range sd.DACL.Entries {
				if ace.Type == ACETYPE_ACCESS_DENIED && ace.SID == OwnerSID {
					aclhasdeny = true
				}
			}
			if !sd.Owner.IsNull() && !aclhasdeny {
				results = append(results, AllObjects.FindOrAddSID(sd.Owner))
			}
			return results
		},
	},
	{
		Method: PwnGenericAll,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_GENERIC_ALL, NullGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnWriteAll,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_GENERIC_WRITE, NullGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnWritePropertyAll,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_WRITE_PROPERTY, NullGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnWriteExtendedAll,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_WRITE_PROPERTY_EXTENDED, NullGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe IMPORTANT
	{
		Method: PwnTakeOwnership,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_WRITE_OWNER, NullGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnWriteDACL,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_WRITE_DACL, NullGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method:      PwnWriteAttributeSecurityGUID,
		Description: `Allows an attacker to modify the attribute security set of an attribute, promoting it to a weaker attribute set`,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			sd, err := o.SecurityDescriptor()
			if o.Type() != ObjectTypeAttributeSchema {
				return results
			}
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_WRITE_PROPERTY, AttributeSecurityGUIDGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnResetPassword,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only computers and users
			if o.Type() != ObjectTypeUser && o.Type() != ObjectTypeComputer && o.Type() != ObjectTypeManagedServiceAccount {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_CONTROL_ACCESS, ResetPwd) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnHasSPN,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only computers and users
			if o.Type() != ObjectTypeUser {
				return results
			}
			if len(o.Attr(ServicePrincipalName)) > 0 {
				o.SetAttr(MetaHasSPN, "1")
				AuthenticatedUsers, found := AllObjects.Find("CN=Authenticated Users,CN=WellKnown Security Principals,CN=Configuration," + AllObjects.Base)
				if !found {
					log.Error().Msgf("Could not locate Authenticated Users")
					return results
				}
				o.PwnableBy.Set(AuthenticatedUsers, PwnHasSPN)
			}
			return results
		},
	},
	{
		Method: PwnHasSPNNoPreauth,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only computers and users
			if o.Type() != ObjectTypeUser {
				return results
			}
			uac, ok := o.AttrInt(UserAccountControl)
			if !ok {
				return results
			}
			if uac&0x400000 == 0 {
				return results
			}
			if len(o.Attr(ServicePrincipalName)) > 0 {
				o.PwnableBy.Set(AttackerObject, PwnHasSPNNoPreauth)
			}
			return results
		},
	},
	{
		Method: PwnWriteSPN, // Same GUID as Validated writes, just a different permission (?)
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only computers and users
			if o.Type() != ObjectTypeUser {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_WRITE_PROPERTY, ValidateWriteSPN) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	/* No real pwnage comes from this, computer passwords are just too hard
	{
		Method: PwnWriteValidatedSPN,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only computers and users
			if o.Type() != ObjectTypeComputer {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o) && acl.AllowMaskedClass(RIGHT_DS_WRITE_PROPERTY_EXTENDED, ValidateWriteSPN) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	}, */
	{
		Method:      PwnWriteAllowedToAct,
		Description: `Modify the msDS-AllowedToActOnBehalfOfOtherIdentity on a computer to enable any SPN enabled user to impersonate anyone else`,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only computers
			if o.Type() != ObjectTypeComputer {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_WRITE_PROPERTY, AttributeAllowedToActOnBehalfOfOtherIdentity) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnAddMember,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for groups
			if o.Type() != ObjectTypeGroup {
				return results
			}
			// It's a group
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_WRITE_PROPERTY, AttributeMember) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnAddMemberGroupAttr,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for groups
			if o.Type() != ObjectTypeGroup {
				return results
			}
			// It's a group
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_WRITE_PROPERTY, AttributeSetGroupMembership) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnAddMember,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for groups
			if o.Type() != ObjectTypeGroup {
				return results
			}
			// It's a group
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_WRITE_PROPERTY_EXTENDED, ValidateWriteSelfMembership) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnReadMSAPassword,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			msasds := o.Attr(MSDSGroupMSAMembership)
			for _, msasd := range msasds {
				sd, err := ParseSecurityDescriptor([]byte(msasd))
				if err == nil {
					for _, acl := range sd.DACL.Entries {
						if acl.Type == ACETYPE_ACCESS_ALLOWED {
							results = append(results, AllObjects.FindOrAddSID(acl.SID))
						}
					}
				}
			}
			return results
		},
	},
	{
		Method:      PwnWriteAltSecurityIdentities,
		Description: "Allows an attacker to define a certificate that can be used to authenticate as the user",
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for users
			if o.Type() != ObjectTypeUser {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_WRITE_PROPERTY, AttributeAltSecurityIdentitiesGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method:      PwnWriteProfilePath,
		Description: "Allows an attacker to trigger a user auth against an attacker controlled UNC path (responder)",
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for users
			if o.Type() != ObjectTypeUser {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_WRITE_PROPERTY, AttributeProfilePathGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method:      PwnWriteScriptPath,
		Description: "Allows an attacker to trigger a user auth against an attacker controlled UNC path (responder)",
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for users
			if o.Type() != ObjectTypeUser {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_WRITE_PROPERTY, AttributeScriptPathGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnHasMSA,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			msas := o.Attr(MSDSHostServiceAccount)
			for _, dn := range msas {
				targetmsa, found := AllObjects.Find(dn)
				if found {
					results = append(results, targetmsa)
				}
			}
			return results
		},
	},
	{
		Method: PwnWriteKeyCredentialLink,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for groups
			if o.Type() != ObjectTypeUser && o.Type() != ObjectTypeComputer {
				return results
			}
			// It's a group
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_WRITE_PROPERTY, AttributeMSDSKeyCredentialLink) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnSIDHistoryEquality,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			sids := o.Attr(SIDHistory)
			for _, stringsid := range sids {
				sid, err := SIDFromString(stringsid)
				if err == nil {
					target := AllObjects.FindOrAddSID(sid)
					results = append(results, target)
				}
			}
			return results
		},
	},
	{
		Method: PwnAllExtendedRights,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// It's a group
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_CONTROL_ACCESS, NullGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnLocalAdminRights,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			var pairs []SIDpair

			groupsxml := o.OneAttr(A("_gpofile/Machine/Preferences/Groups/Groups.XML"))
			if groupsxml != "" {
				pairs = GPOparseGroups(groupsxml)
			}

			groupsini := o.OneAttr(A("_gpofile/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.Inf"))
			if groupsini != "" {
				pairs = append(pairs, GPOparseGptTmplInf(groupsini)...)
			}

			for _, sidpair := range pairs {
				if sidpair.Group == "S-1-5-32-544" {
					membersid, err := SIDFromString(sidpair.Member)
					if err == nil {
						results = append(results, AllObjects.FindOrAddSID(membersid))
					} else {
						log.Warn().Msgf("Detected Local Admin, but could not parse SID %v", sidpair.Member)
					}
				}
				log.Debug().Msgf("%v", sidpair)
			}
			return results
		},
	},
	{
		Method: PwnLocalRDPRights,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			var pairs []SIDpair

			groupsxml := o.OneAttr(A("_gpofile/Machine/Preferences/Groups/Groups.XML"))
			if groupsxml != "" {
				pairs = GPOparseGroups(groupsxml)
			}

			groupsini := o.OneAttr(A("_gpofile/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.Inf"))
			if groupsini != "" {
				pairs = append(pairs, GPOparseGptTmplInf(groupsini)...)
			}

			for _, sidpair := range pairs {
				if sidpair.Group == "S-1-5-32-555" {
					membersid, err := SIDFromString(sidpair.Member)
					if err == nil {
						results = append(results, AllObjects.FindOrAddSID(membersid))
					} else {
						log.Warn().Msgf("Detected Local RDP, but could not parse SID %v", sidpair.Member)
					}
				}
				log.Debug().Msgf("%v", sidpair)
			}
			return results
		},
	},
	{
		Method: PwnLocalDCOMRights,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			var pairs []SIDpair

			groupsxml := o.OneAttr(A("_gpofile/Machine/Preferences/Groups/Groups.XML"))
			if groupsxml != "" {
				pairs = GPOparseGroups(groupsxml)
			}

			groupsini := o.OneAttr(A("_gpofile/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.Inf"))
			if groupsini != "" {
				pairs = append(pairs, GPOparseGptTmplInf(groupsini)...)
			}

			for _, sidpair := range pairs {
				if sidpair.Group == "S-1-5-32-562" {
					membersid, err := SIDFromString(sidpair.Member)
					if err == nil {
						results = append(results, AllObjects.FindOrAddSID(membersid))
					} else {
						log.Warn().Msgf("Detected Local DCOM, but could not parse SID %v", sidpair.Member)
					}
				}
				log.Debug().Msgf("%v", sidpair)
			}
			return results
		},
	},
	{
		Method: PwnCertificateEnroll,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			if o.Type() != ObjectTypeCertificateTemplate {
				return results
			}
			// It's a group
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_CONTROL_ACCESS, ExtendedRightCertificateEnroll) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	},
	{
		Method: PwnScheduledTaskOnUNCPath,
		ObjectAnalyzer: func(o *Object) []*Object {
			schtasksxml := o.OneAttr(A("_gpofile/Machine/Preferences/ScheduledTasks/ScheduledTasks.XML"))
			if schtasksxml == "" {
				return nil
			}
			var results []*Object
			for _, task := range GPOparseScheduledTasks(schtasksxml) {
				log.Debug().Msgf("Scheduled task: %v", task)
				// if sidpair.Group == "S-1-5-32-555" {
				// 	membersid, err := SIDFromString(sidpair.Member)
				// 	if err == nil {
				// 		results = append(results, AllObjects.FindOrAddSID(membersid))
				// 	} else {
				// 		log.Warn().Msgf("Detected Local RDP, but could not parse SID %v", sidpair.Member)
				// 	}
				// }
				// log.Debug().Msgf("%v", sidpair)
			}
			return results
		},
	},

	{
		Method: PwdMachineScript,
		ObjectAnalyzer: func(o *Object) []*Object {
			scripts := o.OneAttr(A("_gpofile/Machine/Scripts/Scripts.ini"))
			if scripts == "" {
				return nil
			}
			var results []*Object

			utf8 := make([]byte, len(scripts)/2)
			_, _, err := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder().Transform(utf8, []byte(scripts), true)
			if err != nil {
				utf8 = []byte(scripts)
			}

			// ini.LineBreak = "\n"

			inifile, err := ini.LoadSources(ini.LoadOptions{
				SkipUnrecognizableLines: true,
			}, utf8)

			scriptnum := 0
			for {
				k1 := inifile.Section("Startup").Key(fmt.Sprintf("%vCmdLine", scriptnum))
				k2 := inifile.Section("Startup").Key(fmt.Sprintf("%vParameters", scriptnum))
				if k1.String() == "" {
					break
				}
				// Create new synthetic object
				sob := NewObject()
				sob.SetAttr(ObjectCategory, "Script")
				sob.DistinguishedName = fmt.Sprintf("CN=Startup Script %v from GPO %v,CN=synthetic", scriptnum, o.OneAttr(Name))
				sob.SetAttr(Name, "Machine startup script "+strings.Trim(k1.String()+" "+k2.String(), " "))
				AllObjects.Add(sob)
				results = append(results, sob)
				scriptnum++
			}

			scriptnum = 0
			for {
				k1 := inifile.Section("Shutdown").Key(fmt.Sprintf("%vCmdLine", scriptnum))
				k2 := inifile.Section("Shutdown").Key(fmt.Sprintf("%vParameters", scriptnum))
				if k1.String() == "" {
					break
				}
				// Create new synthetic object
				sob := NewObject()
				sob.DistinguishedName = fmt.Sprintf("CN=Shutdown Script %v from GPO %v,CN=synthetic", scriptnum, o.OneAttr(Name))
				sob.SetAttr(ObjectCategory, "Script")
				sob.SetAttr(Name, "Machine shutdown script "+strings.Trim(k1.String()+" "+k2.String(), " "))
				AllObjects.Add(sob)
				results = append(results, sob)
				scriptnum++
			}

			return results
		},
	},

	// LAPS password moved to pre-processing, as the attributes have different GUIDs from AD to AD (sigh)
	{
		Method: PwnDCReplicationGetChanges,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChanges) {
					po := AllObjects.FindOrAddSID(acl.SID)
					info := dcsyncobjects[po]
					info.changes = true
					dcsyncobjects[po] = info
				}
			}
			return results
		},
	},
	{
		Method: PwnDCReplicationSyncronize,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_CONTROL_ACCESS, DSReplicationSyncronize) {
					po := AllObjects.FindOrAddSID(acl.SID)
					info := dcsyncobjects[po]
					info.sync = true
					dcsyncobjects[po] = info
				}
			}
			return results
		},
	},
	{
		Method: PwnDSReplicationGetChangesAll,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for index, acl := range sd.DACL.Entries {
				if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChangesAll) {
					po := AllObjects.FindOrAddSID(acl.SID)
					info := dcsyncobjects[po]
					info.all = true
					dcsyncobjects[po] = info
				}
			}
			return results
		},
	},
}

func MakeAdminSDHolderPwnanalyzerFunc(adminsdholder *Object, excluded string) PwnAnalyzer {
	return PwnAnalyzer{
		Method: PwnAdminSDHolderOverwriteACL,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			return results // FIXME

			// Check if object is a user account
			// if o.Type() == ObjectTypeGroup {
			// Let's see if this is a protected group
			// if o.SID() == AccountOperators
			// }

			if o.Type() != ObjectTypeUser {
				return results
			}
			// Check if object is member of one of the protected groups
			// mo := o.Attr(MemberOf)

			//if ac, ok := o.AttrInt(AdminCount); ok && ac > 0 {
			// This object has an AdminCount with a value more than zero, so it kinda can be pwned by the AdminSDHolder container
			results = append(results, adminsdholder)
			//
			return results
		},
	}
}

// Objects that can DC sync
type syncinfo struct {
	changes bool
	sync    bool
	all     bool
}

var dcsyncobjects = make(map[*Object]syncinfo)

type PwnGraph struct {
	Targets     []*Object       // The ones we want to pwn
	Implicated  []*Object       // Everyone implicated, including the targets
	Connections []PwnConnection // Connection to Methods map
}

type PwnPair struct {
	Source, Target *Object
}

type PwnConnection struct {
	Source, Target *Object
	Methods        PwnMethod
}

func AnalyzeObjects(includeobjects, excludeobjects *Objects, methods PwnMethod, mode string, maxdepth int) (pg PwnGraph) {
	connectionsmap := make(map[PwnPair]PwnMethod) // Pwn Connection between objects
	implicatedobjectsmap := make(map[*Object]int) // Object -> Processed in round n

	// Direction to search, forward = who can pwn interestingobjects, !forward = who can interstingobjects pwn
	forward := strings.HasPrefix(mode, "normal")
	// Backlinks = include all links, don't limit per round
	backlinks := strings.HasSuffix(mode, "backlinks")

	// Save this for later
	pg.Targets = includeobjects.AsArray()

	// Convert to our working map
	for _, object := range includeobjects.AsArray() {
		// if !excludeobjects.Contains(object) {
		implicatedobjectsmap[object] = 0
		// }
	}

	somethingprocessed := true
	processinground := 1
	for somethingprocessed && maxdepth >= processinground {
		somethingprocessed = false
		log.Debug().Msgf("Processing round %v with %v total objects", processinground, len(implicatedobjectsmap))
		newimplicatedobjects := make(map[*Object]struct{})
		for object, processed := range implicatedobjectsmap {
			if processed != 0 {
				continue
			}
			somethingprocessed = true

			var pwnlist PwnSet
			if forward {
				pwnlist = object.PwnableBy
			} else {
				pwnlist = object.CanPwn
			}

			for pwntarget, pwninfo := range pwnlist {
				// If this is not a chosen method, skip it
				detectedmethods := pwninfo & methods
				if detectedmethods == 0 || detectedmethods == PwnACLContainsDeny {
					// Nothing useful or just a deny ACL, skip it
					continue
				}

				// If we allow backlinks, all pwns are mapped, no matter who is the victim
				// Targets are allowed to pwn each other as a way to reach the goal of pwning all of them
				// If pwner is already processed, we don't care what it can pwn someone more far away from targets
				// If pwner is our attacker, we always want to know what it can do
				targetprocessinground, found := implicatedobjectsmap[pwntarget]
				if pwntarget != AttackerObject &&
					!backlinks &&
					found &&
					targetprocessinground != 0 &&
					targetprocessinground < processinground {
					// skip it
					continue
				}

				if excludeobjects != nil && excludeobjects.Contains(pwntarget) {
					// skip excluded objects
					// log.Debug().Msgf("Excluding target %v", pwntarget.DN())
					continue
				}

				// Reverse search, stop at domain admins and administrators
				if !forward && (object.OneAttr(Name) == "Domain Admins" ||
					object.OneAttr(Name) == "Enterprise Admins") ||
					object.OneAttr(Name) == "Administrators" {
					continue
				}

				// Append the method to the connection pair
				if forward {
					connectionsmap[PwnPair{Source: pwntarget, Target: object}] = detectedmethods
				} else {
					connectionsmap[PwnPair{Source: object, Target: pwntarget}] = detectedmethods
				}

				if _, found := implicatedobjectsmap[pwntarget]; !found {
					newimplicatedobjects[pwntarget] = struct{}{} // Add this to work map as non-processed
				}
			}
			implicatedobjectsmap[object] = processinground // We're done processing this
		}
		log.Debug().Msgf("Processing round %v yielded %v new objects", processinground, len(newimplicatedobjects))
		for newentry := range newimplicatedobjects {
			implicatedobjectsmap[newentry] = 0
		}
		processinground++
	}

	// Convert map to slice
	pg.Connections = make([]PwnConnection, len(connectionsmap))
	i := 0
	for connection, methods := range connectionsmap {
		pg.Connections[i] = PwnConnection{Source: connection.Source, Target: connection.Target, Methods: methods}
		i++
	}

	pg.Implicated = make([]*Object, len(implicatedobjectsmap))
	i = 0
	for object := range implicatedobjectsmap {
		pg.Implicated[i] = object
		i++
	}

	return
}
