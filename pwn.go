package main

import (
	"strings"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

//go:generate enumer -type=PwnMethod -trimprefix=Pwn -json

// PwnAnalyzer takes an Object, examines it an outputs a list of Objects that can Pwn it
type PwnAnalyzer struct {
	Method         PwnMethod
	ObjectAnalyzer func(o *Object) []*Object
}

type PwnInfo struct {
	Method PwnMethod
	Target *Object
}

// Interesting permissions on AD
var (
	ResetPwd                   = uuid.UUID{0x00, 0x29, 0x95, 0x70, 0x24, 0x6d, 0x11, 0xd0, 0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e, 0x05, 0x29}
	DSReplicationGetChanges    = uuid.UUID{0x11, 0x31, 0xf6, 0xaa, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	DSReplicationGetChangesAll = uuid.UUID{0x11, 0x31, 0xf6, 0xad, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}
	DSReplicationSyncronize    = uuid.UUID{0x11, 0x31, 0xf6, 0xab, 0x9c, 0x07, 0x11, 0xd1, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}

	AttributeMember                 = uuid.UUID{0xbf, 0x96, 0x79, 0xc0, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	AttributeSetGroupMembership     = uuid.UUID{0xBC, 0x0A, 0xC2, 0x40, 0x79, 0xA9, 0x11, 0xD0, 0x90, 0x20, 0x00, 0xC0, 0x4F, 0xC2, 0xD4, 0xCF}
	AttributeSIDHistory             = uuid.UUID{0x17, 0xeb, 0x42, 0x78, 0xd1, 0x67, 0x11, 0xd0, 0xb0, 0x02, 0x00, 0x00, 0xf8, 0x03, 0x67, 0xc1}
	AttributeSPN                    = uuid.UUID{0xf3, 0xa6, 0x47, 0x88, 0x53, 0x06, 0x11, 0xd1, 0xa9, 0xc5, 0x00, 0x00, 0xf8, 0x03, 0x67, 0xc1}
	AttributeAllowedToAct           = uuid.UUID{0x3f, 0x78, 0xc3, 0xe5, 0xf7, 0x9a, 0x46, 0xbd, 0xa0, 0xb8, 0x9d, 0x18, 0x11, 0x6d, 0xdc, 0x79}
	AttributeMSDSGroupMSAMembership = uuid.UUID{0x88, 0x8e, 0xed, 0xd6, 0xce, 0x04, 0xdf, 0x40, 0xb4, 0x62, 0xb8, 0xa5, 0x0e, 0x41, 0xba, 0x38}

	AttributeMSDSKeyCredentialLink, _ = uuid.FromString("{5B47D60F-6090-40B2-9F37-2A4DE88F3063}")

	//  AttributeSecurityGUID	OctetString	1	{9B026DA6-0D3C-465C-8BEE-5199D7165CBA}

	ValidateWriteSelfMembership = uuid.UUID{0xbf, 0x96, 0x79, 0xc0, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ValidateWriteSPN            = uuid.UUID{0xf3, 0xa6, 0x47, 0x88, 0x53, 0x06, 0x11, 0xd1, 0xa9, 0xc5, 0x00, 0x00, 0xf8, 0x03, 0x67, 0xc1}
	ObjectGuidUser              = uuid.UUID{0xbf, 0x96, 0x7a, 0xba, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidComputer          = uuid.UUID{0xbf, 0x96, 0x7a, 0x86, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidGroup             = uuid.UUID{0xbf, 0x96, 0x7a, 0x9c, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}
	ObjectGuidDomain            = uuid.UUID{0x19, 0x19, 0x5a, 0x5a, 0x6d, 0xa0, 0x11, 0xd0, 0xaf, 0xd3, 0x00, 0xc0, 0x4f, 0xd9, 0x30, 0xc9}
	ObjectGuidGPO               = uuid.UUID{0xf3, 0x0e, 0x3b, 0xc2, 0x9f, 0xf0, 0x11, 0xd1, 0xb6, 0x03, 0x00, 0x00, 0xf8, 0x03, 0x67, 0xc1}
	ObjectGuidOU                = uuid.UUID{0xbf, 0x96, 0x7a, 0xa5, 0x0d, 0xe6, 0x11, 0xd0, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}

	NullGUID    = uuid.UUID{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	UnknownGUID = uuid.UUID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	OwnerSID, _        = SIDFromString("S-1-3-4")
	SystemSID, _       = SIDFromString("S-1-5-18")
	CreatorOwnerSID, _ = SIDFromString("S-1-3-0")
	SelfSID, _         = SIDFromString("S-1-5-10")
	AttackerSID, _     = SIDFromString("S-1-555-1337")

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

type PwnMethod byte

const (
	_ PwnMethod = iota
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
	PwnSIDHistoryEquality
	PwnAllExtendedRights
	PwnDCReplicationGetChanges
	PwnDCReplicationSyncronize
	PwnDSReplicationGetChangesAll
	PwnReadLAPSPassword
	PwnMemberOfGroup
	PwnHasSPN
	PwnAdminSDHolderOverwriteACL
)

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
		Method: PwnCreateUser,
		ObjectAnalyzer: func(o *Object) []*Object {
			var results []*Object
			// Only for containers and org units
			if o.Type() != ObjectTypeContainer || o.Type() != ObjectTypeOrganizationalUnit {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_CREATE_CHILD, ObjectGuidUser) {
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
			if o.Type() != ObjectTypeContainer || o.Type() != ObjectTypeOrganizationalUnit {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_CREATE_CHILD, ObjectGuidGroup) {
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
			if o.Type() != ObjectTypeContainer || o.Type() != ObjectTypeOrganizationalUnit {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_CREATE_CHILD, ObjectGuidComputer) {
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
			if o.Type() != ObjectTypeContainer || o.Type() != ObjectTypeOrganizationalUnit {
				return results
			}
			sd, err := o.SecurityDescriptor()
			if err != nil {
				return results
			}
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_CREATE_CHILD, NullGUID) {
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
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DELETE, NullGUID) {
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
				for _, acl := range sd.DACL.Entries {
					if acl.AllowObjectClass(parent.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_DELETE_CHILD, o.ObjectTypeGUID()) {
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
			if o.Type() != ObjectTypeGroup {
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
			for _, acl := range sd.DACL.Entries {
				if (acl.Type == ACETYPE_ACCESS_ALLOWED || (acl.Type == ACETYPE_ACCESS_ALLOWED_OBJECT && acl.ObjectType == NullGUID)) && acl.Mask&RIGHT_GENERIC_ALL != 0 {
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
			for _, acl := range sd.DACL.Entries {
				if acl.Type == ACETYPE_ACCESS_ALLOWED && acl.Mask&RIGHT_GENERIC_WRITE != 0 {
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
			for _, acl := range sd.DACL.Entries {
				if acl.Type == ACETYPE_ACCESS_ALLOWED && acl.Mask&RIGHT_DS_WRITE_PROPERTY != 0 && acl.ObjectType == NullGUID {
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
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.Type == ACETYPE_ACCESS_ALLOWED && acl.Mask&RIGHT_WRITE_OWNER != 0 {
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
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.Type == ACETYPE_ACCESS_ALLOWED && acl.Mask&RIGHT_WRITE_DACL != 0 {
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
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_CONTROL_ACCESS, ResetPwd) {
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
				o.PwnableBy = append(o.PwnableBy, PwnInfo{PwnHasSPN, AttackerObject})
			}
			return results
		},
	},
	{
		Method: PwnWriteSPN,
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
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_WRITE_PROPERTY, AttributeSPN) {
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
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_WRITE_PROPERTY_EXTENDED, ValidateWriteSPN) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
			}
			return results
		},
	}, */
	{
		Method: PwnWriteAllowedToAct,
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
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_WRITE_PROPERTY, AttributeAllowedToAct) {
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
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_WRITE_PROPERTY, AttributeMember) {
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
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_WRITE_PROPERTY, AttributeSetGroupMembership) {
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
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_WRITE_PROPERTY_EXTENDED, ValidateWriteSelfMembership) {
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
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_WRITE_PROPERTY, AttributeMSDSKeyCredentialLink) {
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
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_CONTROL_ACCESS, NullGUID) {
					results = append(results, AllObjects.FindOrAddSID(acl.SID))
				}
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
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChanges) {
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
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_CONTROL_ACCESS, DSReplicationSyncronize) {
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
			for _, acl := range sd.DACL.Entries {
				if acl.AllowObjectClass(o.ObjectTypeGUID()) && acl.AllowMaskedClass(RIGHT_DS_CONTROL_ACCESS, DSReplicationGetChangesAll) {
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
	Methods        []PwnMethod
}

func AnalyzeObjects(includeobjects, excludeobjects *Objects, methods []PwnMethod, mode string, maxdepth int) (pg PwnGraph) {
	connectionsmap := make(map[PwnPair][]PwnMethod) // Pwn Connection between objects
	implicatedobjectsmap := make(map[*Object]int)   // Object -> Processed in round n
	// targetsmap := make(map[*Object]bool)            // Object -> Processed?

	selectedmethodsmap := make([]bool, len(_PwnMethodIndex))
	for _, method := range methods {
		selectedmethodsmap[method] = true
	}

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

			var pwnlist []PwnInfo
			if forward {
				pwnlist = object.PwnableBy
			} else {
				pwnlist = object.CanPwn
			}

			for _, pwninfo := range pwnlist {
				// If this is not a chosen method, skip it
				if !selectedmethodsmap[pwninfo.Method] {
					continue
				}

				// Skip links to prior runs
				pwntarget := pwninfo.Target

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
					continue
				}

				// Append the method to the connection pair
				if forward {
					methods := connectionsmap[PwnPair{Source: pwntarget, Target: object}]
					methods = append(methods, pwninfo.Method)
					connectionsmap[PwnPair{Source: pwntarget, Target: object}] = methods
				} else {
					methods := connectionsmap[PwnPair{Source: object, Target: pwntarget}]
					methods = append(methods, pwninfo.Method)
					connectionsmap[PwnPair{Source: object, Target: pwntarget}] = methods
				}

				// The Pwner is not in the tree, lets add it and see who can Pwn that
				if pwninfo.Method != PwnACLContainsDeny {
					// We don't add deny ACL targets, if they're added because of a positive pwn then it's fine
					if _, found := implicatedobjectsmap[pwntarget]; !found {
						newimplicatedobjects[pwntarget] = struct{}{} // Add this to work map as non-processed
					}
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

	// Remove dangling connections, this is deny ACLs that didn't have the target added
	for conn, _ := range connectionsmap {
		if _, found := implicatedobjectsmap[conn.Source]; !found {
			delete(connectionsmap, conn)
		}
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
