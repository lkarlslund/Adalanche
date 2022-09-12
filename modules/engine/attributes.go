package engine

import (
	"errors"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/ui"
)

var attributenames = make(map[string]Attribute)

type AttributeGetFunc func(o *Object, a Attribute) (v AttributeValues, found bool)
type AttributeSetFunc func(o *Object, a Attribute, v AttributeValues) error

type attributeinfo struct {
	name   string
	tags   []string
	atype  AttributeType
	single bool // If true, this attribute can not have multiple values
	unique bool // Doing a Find on this attribute will return multiple results
	merge  bool // If true, objects can be merged on this attribute
	hidden bool // If true this does not show up in the list of attributes
	onset  AttributeSetFunc
	onget  AttributeGetFunc
}

type AttributeType uint8

const (
	AttributeTypeUnknown AttributeType = iota
	AttributeTypeString
	AttributeTypeInt
	AttributeTypeFloat
	AttributeTypeBool
	AttributeTypeTime
	AttributeTypeSID
	AttributeTypeGUID
	AttributeTypeBlob
)

type mergeapproverinfo struct {
	mergefunc mergefunc
	// priority  int
	name string
}

var mergeapprovers []mergeapproverinfo
var attributenums []attributeinfo

var (
	NonExistingAttribute = Attribute(-1)

	DistinguishedName     = NewAttribute("distinguishedName").Single().Unique()
	ObjectClass           = NewAttribute("objectClass")
	ObjectCategory        = NewAttribute("objectCategory").Single()
	ObjectCategorySimple  = NewAttribute("objectCategorySimple").Single()
	Name                  = NewAttribute("name").Single()
	DisplayName           = NewAttribute("displayName").Single()
	LDAPDisplayName       = NewAttribute("lDAPDisplayName").Single()
	Description           = NewAttribute("description")
	SAMAccountName        = NewAttribute("sAMAccountName").Single()
	ObjectSid             = NewAttribute("objectSid").Single() // Strange yes, but in the final results there are multiple objects with the same SID
	ObjectGUID            = NewAttribute("objectGUID").Single().Unique()
	NTSecurityDescriptor  = NewAttribute("nTSecurityDescriptor").Single()
	SchemaIDGUID          = NewAttribute("schemaIDGUID") // Dirty, needs proper FIXME for multi domain
	RightsGUID            = NewAttribute("rightsGUID")
	AttributeSecurityGUID = NewAttribute("attributeSecurityGUID")

	WhenChanged = NewAttribute("whenChanged").Type(AttributeTypeTime) // Not replicated, so we're not marking it as "single"

	WhenCreated = NewAttribute("whenCreated").Single().Type(AttributeTypeTime)

	ObjectClassGUIDs       = NewAttribute("objectClassGUID")    // Used for caching the GUIDs, should belong in AD analyzer, but it's used in the SecurityDescritor mapping, so we're cheating a bit
	ObjectCategoryGUID     = NewAttribute("objectCategoryGUID") // Used for caching the GUIDs
	IsCriticalSystemObject = NewAttribute("isCriticalSystemObject")

	MetaDataSource = NewAttribute("_datasource")
	UniqueSource   = NewAttribute("_source")

	IPAddress          = NewAttribute("IPAddress")
	DownLevelLogonName = NewAttribute("downLevelLogonName").Merge()
	UserPrincipalName  = NewAttribute("userPrincipalName").Merge()
	NetbiosDomain      = NewAttribute("netbiosDomain") // Used to merge users with - if we only have a DOMAIN\USER type of info
	DomainPart         = NewAttribute("domainPart").Single()

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
)

type Attribute int16

var attributemutex sync.RWMutex

func NewAttribute(name string) Attribute {
	if name[len(name)-1] >= '0' && name[len(name)-1] <= '9' && strings.Index(name, ";") != -1 {
		if !strings.HasPrefix(name, "member;") {
			ui.Debug().Msgf("Incomplete data detected in attribute %v", name)
		}
		pos := strings.Index(name, ";")
		name = name[pos+1:]
	}

	attributemutex.RLock()
	// Case sensitive lookup
	if attribute, found := attributenames[name]; found {
		attributemutex.RUnlock()
		return attribute
	}
	// Lowercase it, do case insensitive lookup
	lowername := strings.ToLower(name)
	if attribute, found := attributenames[lowername]; found {
		attributemutex.RUnlock()
		// If we're here, we have a case insensitive match, but the case was different, so add that
		attributemutex.Lock()
		attributenames[name] = attribute
		attributemutex.Unlock()
		return attribute
	}
	attributemutex.RUnlock()
	attributemutex.Lock()
	// Retry, someone might have beaten us to it
	if attribute, found := attributenames[lowername]; found {
		attributemutex.Unlock()
		return attribute
	}

	newindex := Attribute(len(attributenums))
	attributenames[lowername] = newindex
	attributenames[name] = newindex
	attributenums = append(attributenums, attributeinfo{
		name: name,
	})
	attributemutex.Unlock()

	return Attribute(newindex)
}

func (a Attribute) String() string {
	if a == -1 {
		return "N/A"
	}
	return attributenums[a].name
}

func (a Attribute) Type(t AttributeType) Attribute {
	attributenums[a].atype = t
	return a
}

func (a Attribute) Single() Attribute {
	attributenums[a].single = true
	return a
}

func (a Attribute) IsSingle() bool {
	return attributenums[a].single
}

func (a Attribute) Unique() Attribute {
	attributenums[a].unique = true
	return a
}

func (a Attribute) IsNonUnique() bool {
	return !attributenums[a].unique
}

func (a Attribute) IsUnique() bool {
	return attributenums[a].unique
}

func (a Attribute) Hidden() Attribute {
	attributenums[a].hidden = true
	return a
}

func (a Attribute) IsHidden() bool {
	return attributenums[a].hidden
}

var ErrDontMerge = errors.New("Dont merge objects using any methods")
var ErrMergeOnThis = errors.New("Merge on this attribute")

type mergefunc func(a, b *Object) (*Object, error)

func StandardMerge(attr Attribute, a, b *Object) (*Object, error) {
	return nil, nil
}

func (a Attribute) Merge() Attribute {
	ai := attributenums[a]
	ai.merge = true
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
	ai.tags = append(ai.tags, t)
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

func Attributes() []Attribute {
	var results []Attribute
	attributemutex.RLock()
	for i := range attributenums {
		results = append(results, Attribute(i))
	}
	attributemutex.RUnlock()
	return results
}
