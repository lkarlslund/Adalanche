package activedirectory

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var (
	PwnForeignIdentity = engine.NewPwn("ForeignIdentity")

	DistinguishedName          = engine.NewAttribute("distinguishedName").Tag("AD")
	ObjectClass                = engine.NewAttribute("objectClass").Tag("AD")
	ObjectCategory             = engine.NewAttribute("objectCategory").Tag("AD")
	ObjectCategorySimple       = engine.NewAttribute("objectCategorySimple")
	StructuralObjectClass      = engine.NewAttribute("structuralObjectClass").Tag("AD")
	NTSecurityDescriptor       = engine.NewAttribute("nTSecurityDescriptor").Tag("AD")
	SAMAccountType             = engine.NewAttribute("sAMAccountType").Tag("AD")
	GroupType                  = engine.NewAttribute("groupType").Tag("AD")
	MemberOf                   = engine.NewAttribute("memberOf").Tag("AD")
	AccountExpires             = engine.NewAttribute("accountExpires").Tag("AD")
	RepsTo                     = engine.NewAttribute("repsTo").Tag("AD")
	InstanceType               = engine.NewAttribute("instanceType").Tag("AD")
	ModifiedCount              = engine.NewAttribute("modifiedCount").Tag("AD")
	MinPwdAge                  = engine.NewAttribute("minPwdAge").Tag("AD")
	MinPwdLength               = engine.NewAttribute("minPwdLength").Tag("AD")
	PwdProperties              = engine.NewAttribute("pwdProperties").Tag("AD")
	LockOutDuration            = engine.NewAttribute("lockoutDuration")
	PwdHistoryLength           = engine.NewAttribute("pwdHistoryLength")
	IsCriticalSystemObject     = engine.NewAttribute("isCriticalSystemObject").Tag("AD")
	FSMORoleOwner              = engine.NewAttribute("fSMORoleOwner")
	NTMixedDomain              = engine.NewAttribute("nTMixedDomain")
	SystemFlags                = engine.NewAttribute("systemFlags")
	PrimaryGroupID             = engine.NewAttribute("primaryGroupID").Tag("AD")
	LogonCount                 = engine.NewAttribute("logonCount")
	UserAccountControl         = engine.NewAttribute("userAccountControl").Tag("AD")
	LocalPolicyFlags           = engine.NewAttribute("localPolicyFlags")
	CodePage                   = engine.NewAttribute("codePage")
	CountryCode                = engine.NewAttribute("countryCode")
	OperatingSystem            = engine.NewAttribute("operatingSystem")
	OperatingSystemHotfix      = engine.NewAttribute("operatingSystemHotfix")
	OperatingSystemVersion     = engine.NewAttribute("operatingSystemVersion")
	OperatingSystemServicePack = engine.NewAttribute("operatingSystemServicePack")
	AdminCount                 = engine.NewAttribute("adminCount").Tag("AD")
	LogonHours                 = engine.NewAttribute("logonHours")
	BadPwdCount                = engine.NewAttribute("badPwdCount")
	GPCFileSysPath             = engine.NewAttribute("gPCFileSysPath").Tag("AD")
	SchemaIDGUID               = engine.NewAttribute("schemaIDGUID").Tag("AD")
	PossSuperiors              = engine.NewAttribute("possSuperiors")
	SystemMayContain           = engine.NewAttribute("systemMayContain")
	SystemMustContain          = engine.NewAttribute("systemMustContain")
	ServicePrincipalName       = engine.NewAttribute("servicePrincipalName").Tag("AD")
	Name                       = engine.NewAttribute("name").Tag("AD")
	DisplayName                = engine.NewAttribute("displayName").Tag("AD")
	LDAPDisplayName            = engine.NewAttribute("lDAPDisplayName").Tag("AD") // Attribute-Schema
	Description                = engine.NewAttribute("description").Tag("AD")
	SAMAccountName             = engine.NewAttribute("sAMAccountName").Tag("AD")
	ObjectSid                  = engine.NewAttribute("objectSid").Tag("AD").Merge(func(attr engine.Attribute, a, b *engine.Object) (result *engine.Object, err error) {
		if !a.HasAttrValue(engine.MetaDataSource, engine.AttributeValueString("Active Directory loader")) {
			return nil, engine.ErrMergeOnThis
		}
		if !b.HasAttrValue(engine.MetaDataSource, engine.AttributeValueString("Active Directory loader")) {
			return nil, engine.ErrMergeOnThis
		}

		aisforeign := a.Type() == engine.ObjectTypeForeignSecurityPrincipal
		bisforeign := b.Type() == engine.ObjectTypeForeignSecurityPrincipal

		// If one of the objects is a foreign security principal, we will not merge them
		if (aisforeign || bisforeign) && !(aisforeign && bisforeign) {
			if aisforeign {
				b.PwnsEx(a, PwnForeignIdentity, true)
			} else {
				a.PwnsEx(b, PwnForeignIdentity, true)
			}
			return nil, engine.ErrDontMerge
		}

		if aisforeign && bisforeign {
			// If both are foreign security principals, we will not merge them either
			return nil, engine.ErrDontMerge
		}

		as := a.OneAttrRaw(attr)
		if as == nil {
			return
		}
		asid, ok := as.(windowssecurity.SID)
		if !ok {
			return
		}
		// if a.Label() == "Account Operators" {
		// 	log.Warn().Msgf("GOTCHA %s", asid)
		// }
		// if strings.Contains(a.DN(), "CN=WellKnown") {
		// 	log.Warn().Msgf("GOTCHA WELLKNOWN %s (%s )with SID %s", a.Label(), a.DN(), asid)
		// }
		// if asid.Components() >= 3 && asid.Component(1) == 5 && asid.Component(2) == 32 {
		if asid.Components() >= 3 && asid.Component(1) == 5 && asid.Component(2) != 21 {
			return nil, engine.ErrDontMerge
		}
		return
	})
	ObjectGUID                  = engine.NewAttribute("objectGUID").Tag("AD").Merge(nil)
	PwdLastSet                  = engine.NewAttribute("pwdLastSet").Tag("AD")
	WhenCreated                 = engine.NewAttribute("whenCreated")
	WhenChanged                 = engine.NewAttribute("whenChanged")
	DsCorePropagationData       = engine.NewAttribute("dsCorePropagationData")
	MsExchLastUpdateTime        = engine.NewAttribute("msExchLastUpdateTime")
	GWARTLastModified           = engine.NewAttribute("gWARTLastModified")
	SpaceLastComputed           = engine.NewAttribute("spaceLastComputed")
	MsExchPolicyLastAppliedTime = engine.NewAttribute("msExchPolicyLastAppliedTime")
	MsExchWhenMailboxCreated    = engine.NewAttribute("msExchWhenMailboxCreated")
	SIDHistory                  = engine.NewAttribute("sIDHistory").Tag("AD")
	LastLogon                   = engine.NewAttribute("lastLogon")
	LastLogonTimestamp          = engine.NewAttribute("lastLogonTimestamp")
	MSDSGroupMSAMembership      = engine.NewAttribute("msDS-GroupMSAMembership").Tag("AD")
	MSDSHostServiceAccount      = engine.NewAttribute("msDS-HostServiceAccount").Tag("AD")
	MSDSHostServiceAccountBL    = engine.NewAttribute("msDS-HostServiceAccountBL").Tag("AD")
	MSmcsAdmPwdExpirationTime   = engine.NewAttribute("ms-mcs-AdmPwdExpirationTime").Tag("AD") // LAPS password timeout
	SecurityIdentifier          = engine.NewAttribute("securityIdentifier")
	TrustDirection              = engine.NewAttribute("trustDirection")
	TrustAttributes             = engine.NewAttribute("trustAttributes")
	TrustPartner                = engine.NewAttribute("trustPartner")
	DsHeuristics                = engine.NewAttribute("dsHeuristics").Tag("AD")
	AttributeSecurityGUID       = engine.NewAttribute("attributeSecurityGUID").Tag("AD")
	MSDSConsistencyGUID         = engine.NewAttribute("mS-DS-ConsistencyGuid")
	RightsGUID                  = engine.NewAttribute("rightsGUID").Tag("AD")
	GPLink                      = engine.NewAttribute("gPLink").Tag("AD")
	GPOptions                   = engine.NewAttribute("gPOptions").Tag("AD")
	ScriptPath                  = engine.NewAttribute("scriptPath").Tag("AD")
	MSPKICertificateNameFlag    = engine.NewAttribute("msPKI-Certificate-Name-Flag").Tag("AD")
	PKIExtendedUsage            = engine.NewAttribute("pKIExtendedKeyUsage").Tag("AD")
)
