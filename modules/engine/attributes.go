package engine

import (
	"errors"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

var attributenames = make(map[string]Attribute)

type AttributeGetFunc func(o *Object, a Attribute) (v AttributeValues, found bool)
type AttributeSetFunc func(o *Object, a Attribute, v AttributeValues) error

type attributeinfo struct {
	Name                         string
	Tags                         []string
	Type                         AttributeType
	Single                       bool // If true, this attribute can not have multiple values
	Unique                       bool // Doing a Find on this attribute will return multiple results
	Merge                        bool // If true, objects can be merged on this attribute
	DefaultF, DefaultM, DefaultL bool
	onset                        AttributeSetFunc
	onget                        AttributeGetFunc
}

type AttributeType uint8

const (
	AttributeTypeString AttributeType = iota
	AttributeTypeInt
	AttributeTypeFloat
	AttributeTypeBool
	AttributeTypeTime
)

type mergeapproverinfo struct {
	mergefunc mergefunc
	// priority  int
	name string
}

var mergeapprovers []mergeapproverinfo
var attributenums []attributeinfo

var (
	NonExistingAttribute = NewAttribute("*NON EXISTING ATTRIBUTE*")

	DistinguishedName     = NewAttribute("distinguishedName").Single().Unique()
	ObjectClass           = NewAttribute("objectClass")
	ObjectCategory        = NewAttribute("objectCategory").Single()
	ObjectCategorySimple  = NewAttribute("objectCategorySimple").Single()
	Name                  = NewAttribute("name").Single()
	DisplayName           = NewAttribute("displayName").Single()
	LDAPDisplayName       = NewAttribute("lDAPDisplayName").Single()
	Description           = NewAttribute("description").Single()
	SAMAccountName        = NewAttribute("sAMAccountName").Single()
	ObjectSid             = NewAttribute("objectSid").Single() // Strange yes, but in the final results there are multiple objects with the same SID
	ObjectGUID            = NewAttribute("objectGUID").Single().Unique()
	NTSecurityDescriptor  = NewAttribute("nTSecurityDescriptor").Single()
	SchemaIDGUID          = NewAttribute("schemaIDGUID") // Dirty, needs proper FIXME for multi domain
	RightsGUID            = NewAttribute("rightsGUID")
	AttributeSecurityGUID = NewAttribute("attributeSecurityGUID")

	WhenCreated = NewAttribute("whenCreated").Single()

	ObjectClassGUIDs       = NewAttribute("objectClassGUID")    // Used for caching the GUIDs, should belong in AD analyzer, but it's used in the SecurityDescritor mapping, so we're cheating a bit
	ObjectCategoryGUID     = NewAttribute("objectCategoryGUID") // Used for caching the GUIDs
	IsCriticalSystemObject = NewAttribute("isCriticalSystemObject")

	MetaDataSource = NewAttribute("_datasource")
	UniqueSource   = NewAttribute("_source").Single()

	IPAddress          = NewAttribute("IPAddress")
	Hostname           = NewAttribute("hostname").Merge()
	DownLevelLogonName = NewAttribute("downLevelLogonName").Merge()
	UserPrincipalName  = NewAttribute("userPrincipalName").Merge()
	NetbiosDomain      = NewAttribute("netbiosDomain") // Used to merge users with - if we only have a DOMAIN\USER type of info

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
	MetaLAPSInstalled           = NewAttribute("_haslaps")
	// The rest is skipped
	_ = NewAttribute("member")
	_ = NewAttribute("member;range=0-4999")
	_ = NewAttribute("proxyAddresses")
	_ = NewAttribute("dSCorePropagationData")
)

type Attribute uint16

var attributemutex sync.RWMutex

func NewAttribute(name string) Attribute {
	if name[len(name)-1] >= '0' && name[len(name)-1] <= '9' && strings.Index(name, ";") != -1 {
		if !strings.HasPrefix(name, "member;") {
			log.Debug().Msgf("Incomplete data detected in attribute %v", name)
		}
		pos := strings.Index(name, ";")
		name = name[pos+1:]
	}

	// Lowercase it, everything is case insensitive
	lowername := strings.ToLower(name)

	attributemutex.RLock()
	if attribute, found := attributenames[lowername]; found {
		attributemutex.RUnlock()
		return attribute
	}
	attributemutex.RUnlock()
	attributemutex.Lock()
	// Retry, someone might have beaten us to it
	if attribute, found := attributenames[lowername]; found {
		attributemutex.Unlock()
		return attribute
	}

	newindex := Attribute(len(attributenames))
	attributenames[lowername] = newindex
	attributenums = append(attributenums, attributeinfo{
		Name:     name,
		DefaultF: true,
		DefaultM: true,
		DefaultL: true,
	})
	attributemutex.Unlock()

	return Attribute(newindex)
}

func (a Attribute) String() string {
	return attributenums[a].Name
}

func (a Attribute) Type(t AttributeType) Attribute {
	ai := attributenums[a]
	ai.Type = t
	attributenums[a] = ai
	return a
}

func (a Attribute) Single() Attribute {
	ai := attributenums[a]
	ai.Single = true
	attributenums[a] = ai
	return a
}

func (a Attribute) IsSingle() bool {
	ai := attributenums[a]
	return ai.Single
}

func (a Attribute) Unique() Attribute {
	ai := attributenums[a]
	ai.Unique = true
	attributenums[a] = ai
	return a
}

func (a Attribute) IsNonUnique() bool {
	ai := attributenums[a]
	return !ai.Unique
}

func (a Attribute) IsUnique() bool {
	ai := attributenums[a]
	return ai.Unique
}

var ErrDontMerge = errors.New("Dont merge objects using any methods")
var ErrMergeOnThis = errors.New("Merge on this attribute")

type mergefunc func(a, b *Object) (*Object, error)

func StandardMerge(attr Attribute, a, b *Object) (*Object, error) {
	return nil, nil
}

func (a Attribute) Merge() Attribute {
	ai := attributenums[a]
	ai.Merge = true
	attributenums[a] = ai
	return a
}

func AddMergeApprover(name string, mf mergefunc) {
	mergeapprovers = append(mergeapprovers, mergeapproverinfo{
		name:      name,
		mergefunc: mf,
	})
}

func (a Attribute) Tag(t string) Attribute {
	ai := attributenums[a]
	ai.Tags = append(ai.Tags, t)
	attributenums[a] = ai
	return a
}

func (a Attribute) OnSet(onset AttributeSetFunc) Attribute {
	ai := attributenums[a]
	ai.onset = onset
	attributenums[a] = ai
	return a
}

func (a Attribute) OnGet(onget AttributeGetFunc) Attribute {
	ai := attributenums[a]
	ai.onget = onget
	attributenums[a] = ai
	return a
}

func LookupAttribute(name string) Attribute {
	attributemutex.RLock()
	defer attributemutex.RUnlock()
	if attribute, found := attributenames[strings.ToLower(name)]; found {
		return attribute
	}
	return NonExistingAttribute
}

func A(name string) Attribute {
	return LookupAttribute(name)
}

func (a Attribute) IsMeta() bool {
	return strings.HasPrefix(a.String(), "_")
}
