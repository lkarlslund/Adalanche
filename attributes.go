package main

import (
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
)

var attributenames = make(map[string]Attribute)
var attributenums []string
var attributepopularity []int
var attributesizes []int

var (
	NonExistingAttribute        = NewAttribute("*NON EXISTING ATTRIBUTE*")
	DistinguishedName           = NewAttribute("distinguishedName")
	ObjectClass                 = NewAttribute("objectClass")
	ObjectCategory              = NewAttribute("objectCategory")
	StructuralObjectClass       = NewAttribute("structuralObjectClass")
	NTSecurityDescriptor        = NewAttribute("nTSecurityDescriptor")
	SAMAccountType              = NewAttribute("sAMAccountType")
	GroupType                   = NewAttribute("groupType")
	MemberOf                    = NewAttribute("memberOf")
	AccountExpires              = NewAttribute("accountExpires")
	RepsTo                      = NewAttribute("repsTo")
	InstanceType                = NewAttribute("instanceType")
	ModifiedCount               = NewAttribute("modifiedCount")
	MinPwdAge                   = NewAttribute("minPwdAge")
	MinPwdLength                = NewAttribute("minPwdLength")
	PwdProperties               = NewAttribute("pwdProperties")
	LockOutDuration             = NewAttribute("lockoutDuration")
	PwdHistoryLength            = NewAttribute("pwdHistoryLength")
	IsCriticalSystemObject      = NewAttribute("isCriticalSystemObject")
	FSMORoleOwner               = NewAttribute("fSMORoleOwner")
	NTMixedDomain               = NewAttribute("nTMixedDomain")
	SystemFlags                 = NewAttribute("systemFlags")
	PrimaryGroupID              = NewAttribute("primaryGroupID")
	LogonCount                  = NewAttribute("logonCount")
	UserAccountControl          = NewAttribute("userAccountControl")
	LocalPolicyFlags            = NewAttribute("localPolicyFlags")
	CodePage                    = NewAttribute("codePage")
	CountryCode                 = NewAttribute("countryCode")
	OperatingSystem             = NewAttribute("operatingSystem")
	OperatingSystemHotfix       = NewAttribute("operatingSystemHotfix")
	OperatingSystemVersion      = NewAttribute("operatingSystemVersion")
	OperatingSystemServicePack  = NewAttribute("operatingSystemServicePack")
	AdminCount                  = NewAttribute("adminCount")
	LogonHours                  = NewAttribute("logonHours")
	BadPwdCount                 = NewAttribute("badPwdCount")
	MAX_DEDUP                   = BadPwdCount
	SchemaIDGUID                = NewAttribute("schemaIDGUID")
	ServicePrincipalName        = NewAttribute("servicePrincipalName")
	Name                        = NewAttribute("name")
	DisplayName                 = NewAttribute("displayName")
	LDAPDisplayName             = NewAttribute("lDAPDisplayName") // Attribute-Schema
	Description                 = NewAttribute("description")
	SAMAccountName              = NewAttribute("sAMAccountName")
	ObjectSid                   = NewAttribute("objectSid")
	ObjectGUID                  = NewAttribute("objectGUID")
	PwdLastSet                  = NewAttribute("pwdLastSet")
	WhenCreated                 = NewAttribute("whenCreated")
	WhenChanged                 = NewAttribute("whenChanged")
	SIDHistory                  = NewAttribute("sIDHistory")
	LastLogon                   = NewAttribute("lastLogon")
	LastLogonTimestamp          = NewAttribute("lastLogonTimestamp")
	MSDSGroupMSAMembership      = NewAttribute("msDS-GroupMSAMembership")
	MSDSHostServiceAccount      = NewAttribute("msDS-HostServiceAccount")
	MSDSHostServiceAccountBL    = NewAttribute("msDS-HostServiceAccountBL")
	MSmcsAdmPwdExpirationTime   = NewAttribute("ms-mcs-AdmPwdExpirationTime") // LAPS password timeout
	SecurityIdentifier          = NewAttribute("securityIdentifier")
	TrustDirection              = NewAttribute("trustDirection")
	TrustAttributes             = NewAttribute("trustAttributes")
	TrustPartner                = NewAttribute("trustPartner")
	DsHeuristics                = NewAttribute("dsHeuristics")
	AttributeSecurityGUID       = NewAttribute("attributeSecurityGUID")
	GPLink                      = NewAttribute("gPLink")
	GPOptions                   = NewAttribute("gPOptions")
	ScriptPath                  = NewAttribute("scriptPath")
	MAX_IMPORTED                = ScriptPath
	MetaProtectedUser           = NewAttribute("_protecteduser")
	MetaUnconstrainedDelegation = NewAttribute("_unconstraineddelegation")
	MetaConstrainedDelegation   = NewAttribute("_constraineddelegation")
	MetaHasSPN                  = NewAttribute("_hasspn")
	MetaPasswordAge             = NewAttribute("_passwordage")
	MetaLastLoginAge            = NewAttribute("_lastloginage")
	MetaAccountDisabled         = NewAttribute("_accountdisabled")
	MetaPasswordCantChange      = NewAttribute("_passwordcantchange")
	MetaPasswordNotRequired     = NewAttribute("_passwordnotrequired")
	MetaPasswordNoExpire        = NewAttribute("_passwordnoexpire")
	MetaLinux                   = NewAttribute("_linux")
	MetaWindows                 = NewAttribute("_windows")
	MetaWorkstation             = NewAttribute("_workstation")
	MetaServer                  = NewAttribute("_server")
	MetaType                    = NewAttribute("_type")
	MetaLAPSInstalled           = NewAttribute("_haslaps")
	// The rest is skipped
	_ = NewAttribute("member")
	_ = NewAttribute("member;range=0-4999")
	_ = NewAttribute("proxyAddresses")
	_ = NewAttribute("dSCorePropagationData")
)

type Attribute uint16

func NewAttribute(name string) Attribute {
	if pos := strings.Index(name, ";"); pos != -1 {
		if !strings.HasPrefix(name, "member;") {
			log.Debug().Msgf("Incomplete data detected in attribute %v", name)
		}
		name = name[pos+1:]
	}

	// Lowercase it, everything is case insensitive
	name = strings.ToLower(name)

	if attribute, found := attributenames[name]; found {
		attributepopularity[attribute]++
		return attribute
	}
	newindex := Attribute(len(attributenames))
	attributenames[name] = newindex
	attributenums = append(attributenums, name)
	attributepopularity = append(attributepopularity, 1)
	attributesizes = append(attributesizes, 0)
	return Attribute(newindex)
}

func (a Attribute) String() string {
	return attributenums[a]
}

func LookupAttribute(name string) Attribute {
	if attribute, found := attributenames[name]; found {
		return attribute
	}
	return NonExistingAttribute
}

func A(name string) Attribute {
	return LookupAttribute(strings.ToLower(name))
}

func (a Attribute) IsMeta() bool {
	return strings.HasPrefix(a.String(), "_")
}

type orderedPair struct {
	key   Attribute
	count int
}
type pairList []orderedPair

func rankByCount(popularity []int) pairList {
	pl := make(pairList, len(popularity))
	i := 0
	for k, v := range popularity {
		pl[i] = orderedPair{Attribute(k), v}
		i++
	}
	sort.Sort(sort.Reverse(pl))
	return pl
}

func (p pairList) Len() int           { return len(p) }
func (p pairList) Less(i, j int) bool { return p[i].count < p[j].count }
func (p pairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func ShowAttributePopularity() {
	log.Debug().Msg("¤¤¤¤¤¤¤¤¤¤¤ COUNTS ############")
	for _, pair := range rankByCount(attributepopularity) {
		log.Debug().Msgf("%v has %v hits", pair.key.String(), pair.count)
	}
	log.Debug().Msg("¤¤¤¤¤¤¤¤¤¤¤ SIZES ############")
	for _, pair := range rankByCount(attributesizes) {
		log.Debug().Msgf("%v has used %v bytes", pair.key.String(), pair.count)
	}
}
