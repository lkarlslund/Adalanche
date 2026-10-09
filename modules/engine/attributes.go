package engine

import (
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/ui"
)

var attributenames = make(map[string]Attribute)

type AttributeGetFunc func(o *Node, a Attribute) (v AttributeValues, found bool)
type AttributeSetFunc func(o *Node, a Attribute, v AttributeValues) error

type attributeinfo struct {
	onset       AttributeSetFunc
	onget       AttributeGetFunc
	name        string
	description string
	tags        []string
	atype       AttributeType
	flags       AttributeFlag
}

type AttributeFlag uint64

const (
	AttributeFlagNone AttributeFlag = 1 << iota
	Hidden                          // Don't expose this when displaying node info in the UI
	Unique                          // Contents is truly unique across all nodes
	Merge                           // Try to merge on this
	Single                          // Can only hold one value
	DropWhenMerging                 // Node being merged from does not contribute this attribute
	Fuzzy                           // A Merge key that names a thing loosely, such as an address; tried after strict keys
	Secret                          // Holds a password, key or other secret; kept out of what other tools are given
)

type AttributeType uint8

const (
	AttributeTypeUnknown AttributeType = iota
	AttributeTypeString
	AttributeTypeInt
	AttributeTypeFloat
	AttributeTypeBool
	AttributeTypeTime
	AttributeTypeTime100NS
	AttributeTypeSID
	AttributeTypeGUID
	AttributeTypeBlob
	AttributeTypeSecurityDescriptor
)

var attributeinfos []attributeinfo

var (
	NonExistingAttribute = ^Attribute(0)

	DistinguishedName = NewAttribute("distinguishedName").Flag(Single, Unique, Merge)
	ObjectClass       = NewAttribute("objectClass")
	ObjectCategory    = NewAttribute("objectCategory").Flag(Single)
	Type              = NewAttribute("type").Flag(Single)
	Name              = NewAttribute("name").Flag(Single)
	DisplayName       = NewAttribute("displayName").Flag(Single)
	LDAPDisplayName   = NewAttribute("lDAPDisplayName").Flag(Single)
	Description       = NewAttribute("description")
	SAMAccountName    = NewAttribute("sAMAccountName").Flag(Single)
	// ObjectSid is single-valued but not unique: builtin and machine SIDs
	// repeat per domain and machine, so references by SID carry a scope.
	ObjectSid             = NewAttribute("objectSid").Flag(Single, Merge)
	ObjectGUID            = NewAttribute("objectGUID").Flag(Single, Merge, Unique)
	NTSecurityDescriptor  = NewAttribute("nTSecurityDescriptor").Flag(Single)
	SchemaIDGUID          = NewAttribute("schemaIDGUID")
	RightsGUID            = NewAttribute("rightsGUID")
	AttributeSecurityGUID = NewAttribute("attributeSecurityGUID")

	WhenChanged = NewAttribute("whenChanged").Type(AttributeTypeTime) // Not replicated, so we're not marking it as "single"

	WhenCreated = NewAttribute("whenCreated").Flag(Single).Type(AttributeTypeTime)

	ObjectClassGUIDs       = NewAttribute("objectClassGUID")    // Used for caching the GUIDs, should belong in AD analyzer, but it's used in the SecurityDescritor mapping, so we're cheating a bit
	ObjectCategoryGUID     = NewAttribute("objectCategoryGUID") // Used for caching the GUIDs
	IsCriticalSystemObject = NewAttribute("isCriticalSystemObject")

	DataLoader = NewAttribute("dataLoader").SetDescription("Where did data in this object come from")
	DataSource = NewAttribute("dataSource").SetDescription("Data from different sources are never merged together")

	IPAddress          = NewAttribute("iPAddress").Flag(Merge, Fuzzy)
	DownLevelLogonName = NewAttribute("downLevelLogonName").Flag(Merge, Single)
	// An account logs on under several names in UPN form (its explicit
	// UPN, the implicit sAMAccountName@dnsdomain), so this is not single.
	UserPrincipalName = NewAttribute("userPrincipalName").Flag(Merge)
	NetbiosDomain     = NewAttribute("netbiosDomain").Flag(Single) // Used to merge users with - if we only have a DOMAIN\USER type of info
	DomainContext     = NewAttribute("domainContext").Flag(Single)

	Tag = NewAttribute("tag")
)

type Attribute uint16

type AttributePair struct {
	attribute1 Attribute
	attribute2 Attribute
}

var attributemutex sync.RWMutex

func NewAttribute(name string) Attribute {
	if name[len(name)-1] >= '0' && name[len(name)-1] <= '9' && strings.Contains(name, ";") {
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

	newindex := Attribute(len(attributeinfos))
	attributenames[lowername] = newindex
	attributenames[name] = newindex
	attributeinfos = append(attributeinfos, attributeinfo{
		name: name,
	})
	attributemutex.Unlock()

	return Attribute(newindex)
}

func (a Attribute) String() string {
	if a == NonExistingAttribute {
		return "N/A"
	}
	result := attributeinfos[a].name
	return result
}

func (a Attribute) Type(t AttributeType) Attribute {
	attributeinfos[a].atype = t
	return a
}

// AttributeType returns the type values of the attribute are stored as.
func (a Attribute) AttributeType() AttributeType {
	attributemutex.RLock()
	defer attributemutex.RUnlock()
	return attributeinfos[a].atype
}

func (a Attribute) Flag(flags ...AttributeFlag) Attribute {
	for _, flag := range flags {
		attributeinfos[a].flags |= flag
	}
	return a
}

func (a Attribute) HasFlag(flag AttributeFlag) bool {
	return (attributeinfos[a].flags & flag) != 0
}

func (a Attribute) Tag(t string) Attribute {
	attributemutex.Lock()
	attributeinfos[a].tags = append(attributeinfos[a].tags, t)
	attributemutex.Unlock()
	return a
}

func (a Attribute) SetDescription(t string) Attribute {
	attributemutex.Lock()
	attributeinfos[a].description = t
	attributemutex.Unlock()
	return a
}

func (a Attribute) OnSet(onset AttributeSetFunc) Attribute {
	attributemutex.Lock()
	attributeinfos[a].onset = onset
	attributemutex.Unlock()
	return a
}

func (a Attribute) OnGet(onget AttributeGetFunc) Attribute {
	attributemutex.Lock()
	attributeinfos[a].onget = onget
	attributemutex.Unlock()
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
	for i := range attributeinfos {
		results = append(results, Attribute(i))
	}
	attributemutex.RUnlock()
	return results
}

func AttributeInfos() []attributeinfo {
	result := make([]attributeinfo, len(attributeinfos))
	attributemutex.RLock()
	copy(result, attributeinfos)
	attributemutex.RUnlock()
	return result
}
