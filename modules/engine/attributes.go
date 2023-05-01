package engine

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lkarlslund/adalanche/modules/ui"
)

var attributenames = make(map[string]Attribute)

type AttributeGetFunc func(o *Object, a Attribute) (v AttributeValues, found bool)
type AttributeSetFunc func(o *Object, a Attribute, v AttributeValues) error

type attributeinfo struct {
	onset          AttributeSetFunc
	onget          AttributeGetFunc
	name           string
	tags           []string
	description    string
	mergeSuccesses atomic.Uint64 // number of successfull merges where this attribute was the deciding factor
	atype          AttributeType
	single         bool // If true, this attribute can not have multiple values
	unique         bool // Doing a Find on this attribute will return multiple results
	merge          bool // If true, objects can be merged on this attribute
	hidden         bool // If true this does not show up in the list of attributes
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
	NonExistingAttribute = ^Attribute(0)

	DistinguishedName     = NewAttribute("distinguishedName").Single().Unique()
	ObjectClass           = NewAttribute("objectClass")
	ObjectCategory        = NewAttribute("objectCategory").Single()
	ObjectCategorySimple  = NewAttribute("objectCategorySimple").Single()
	Name                  = NewAttribute("name").Single()
	DisplayName           = NewAttribute("displayName").Single()
	LDAPDisplayName       = NewAttribute("lDAPDisplayName").Single()
	Description           = NewAttribute("description")
	SAMAccountName        = NewAttribute("sAMAccountName").Single()
	ObjectSid             = NewAttribute("objectSid").Single() // Single, but not unique! Strange yes, but in the final results there are multiple objects with the same SID
	ObjectGUID            = NewAttribute("objectGUID").Single().Merge().Unique()
	NTSecurityDescriptor  = NewAttribute("nTSecurityDescriptor").Single()
	SchemaIDGUID          = NewAttribute("schemaIDGUID")
	RightsGUID            = NewAttribute("rightsGUID")
	AttributeSecurityGUID = NewAttribute("attributeSecurityGUID")

	WhenChanged = NewAttribute("whenChanged").Type(AttributeTypeTime) // Not replicated, so we're not marking it as "single"

	WhenCreated = NewAttribute("whenCreated").Single().Type(AttributeTypeTime)

	ObjectClassGUIDs       = NewAttribute("objectClassGUID")    // Used for caching the GUIDs, should belong in AD analyzer, but it's used in the SecurityDescritor mapping, so we're cheating a bit
	ObjectCategoryGUID     = NewAttribute("objectCategoryGUID") // Used for caching the GUIDs
	IsCriticalSystemObject = NewAttribute("isCriticalSystemObject")

	DataLoader = NewAttribute("dataLoader")
	DataSource = NewAttribute("dataSource")

	IPAddress          = NewAttribute("IPAddress")
	DownLevelLogonName = NewAttribute("downLevelLogonName").Merge()
	UserPrincipalName  = NewAttribute("userPrincipalName").Merge()
	NetbiosDomain      = NewAttribute("netbiosDomain").Single() // Used to merge users with - if we only have a DOMAIN\USER type of info
	DomainContext      = NewAttribute("domainContext").Single()

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

func init() {
	AddMergeApprover("Merge SIDs", func(a, b *Object) (*Object, error) {
		asid := a.SID()
		bsid := b.SID()
		if asid.IsBlank() || bsid.IsBlank() {
			return nil, nil
		}
		if asid != bsid {
			return nil, ErrDontMerge
		}
		if asid.Component(2) == 21 {
			return nil, nil // Merge, these should be universally mappable !?
		}
		asource := a.OneAttr(DataSource)
		bsource := b.OneAttr(DataSource)
		if CompareAttributeValues(asource, bsource) {
			// Stuff from GPOs can have non universal SIDs but should still be mapped
			return nil, nil
		}
		return nil, ErrDontMerge
	})
}

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
	if a == NonExistingAttribute {
		return "N/A"
	}
	attributemutex.RLock()
	result := attributenums[a].name
	attributemutex.RUnlock()
	return result
}

func (a Attribute) Type(t AttributeType) Attribute {
	attributemutex.Lock()
	attributenums[a].atype = t
	attributemutex.Unlock()
	return a
}

func (a Attribute) Single() Attribute {
	attributemutex.Lock()
	attributenums[a].single = true
	attributemutex.Unlock()
	return a
}

func (a Attribute) IsSingle() bool {
	attributemutex.RLock()
	result := attributenums[a].single
	attributemutex.RUnlock()
	return result
}

func (a Attribute) Unique() Attribute {
	attributemutex.Lock()
	attributenums[a].unique = true
	attributemutex.Unlock()
	return a
}

func (a Attribute) IsNonUnique() bool {
	attributemutex.RLock()
	result := !attributenums[a].unique
	attributemutex.RUnlock()
	return result
}

func (a Attribute) IsUnique() bool {
	attributemutex.RLock()
	result := attributenums[a].unique
	attributemutex.RUnlock()
	return result
}

func (a Attribute) Hidden() Attribute {
	attributemutex.Lock()
	attributenums[a].hidden = true
	attributemutex.Unlock()
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
	attributemutex.Lock()
	attributenums[a].merge = true
	attributemutex.Unlock()
	return a
}

func AddMergeApprover(name string, mf mergefunc) {
	attributemutex.Lock()
	mergeapprovers = append(mergeapprovers, mergeapproverinfo{
		name:      name,
		mergefunc: mf,
	})
	attributemutex.Unlock()
}

func (a Attribute) Tag(t string) Attribute {
	attributemutex.Lock()
	attributenums[a].tags = append(attributenums[a].tags, t)
	attributemutex.Unlock()
	return a
}

func (a Attribute) SetDescription(t string) Attribute {
	attributemutex.Lock()
	attributenums[a].description = t
	attributemutex.Unlock()
	return a
}

func (a Attribute) OnSet(onset AttributeSetFunc) Attribute {
	attributemutex.Lock()
	attributenums[a].onset = onset
	attributemutex.Unlock()
	return a
}

func (a Attribute) OnGet(onget AttributeGetFunc) Attribute {
	attributemutex.Lock()
	attributenums[a].onget = onget
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
	for i := range attributenums {
		results = append(results, Attribute(i))
	}
	attributemutex.RUnlock()
	return results
}
