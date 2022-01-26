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
	name      string
	tags      []string
	multi     bool // If true, this attribute can have multiple values
	nonunique bool // Doing a Find on this attribute will return multiple results
	merge     bool // If true, objects can be merged on this attribute
	mf        mergefunc
	onset     AttributeSetFunc
	onget     AttributeGetFunc
}

var attributenums []attributeinfo

var (
	NonExistingAttribute = NewAttribute("*NON EXISTING ATTRIBUTE*")

	DistinguishedName     = NewAttribute("distinguishedName")
	ObjectClass           = NewAttribute("objectClass")
	ObjectCategory        = NewAttribute("objectCategory")
	ObjectCategorySimple  = NewAttribute("objectCategorySimple")
	Name                  = NewAttribute("name")
	DisplayName           = NewAttribute("displayName")
	LDAPDisplayName       = NewAttribute("lDAPDisplayName")
	Description           = NewAttribute("description")
	SAMAccountName        = NewAttribute("sAMAccountName")
	ObjectSid             = NewAttribute("objectSid")
	ObjectGUID            = NewAttribute("objectGUID")
	NTSecurityDescriptor  = NewAttribute("nTSecurityDescriptor")
	SchemaIDGUID          = NewAttribute("schemaIDGUID")
	RightsGUID            = NewAttribute("rightsGUID")
	AttributeSecurityGUID = NewAttribute("attributeSecurityGUID")

	dummyflag    = NewAttribute("dummyflag")
	MAX_IMPORTED = dummyflag

	ObjectClassGUIDs   = NewAttribute("objectClassGUID")    // Used for caching the GUIDs, should belong in AD analyzer, but it's used in the SecurityDescritor mapping, so we're cheating a bit
	ObjectCategoryGUID = NewAttribute("objectCategoryGUID") // Used for caching the GUIDs

	MetaDataSource = NewAttribute("_datasource").Multi()
	UniqueSource   = NewAttribute("_source").Merge(func(attr Attribute, a, b *Object) (*Object, error) {
		// Prevents objects from vastly different sources to join across them
		if a.HasAttr(attr) && b.HasAttr(attr) && a.OneAttrString(attr) != b.OneAttrString(attr) {
			return nil, ErrDontMerge
		}
		return nil, ErrMergeOnOtherAttr
	})

	IPAddress          = NewAttribute("IPAddress")
	Hostname           = NewAttribute("Hostname").Merge(nil)
	DownLevelLogonName = NewAttribute("DownLevelLogonName").Merge(nil)
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
	attributenums = append(attributenums, attributeinfo{name: name})
	attributemutex.Unlock()

	return Attribute(newindex)
}

func (a Attribute) String() string {
	return attributenums[a].name
}

func (a Attribute) Multi() Attribute {
	ai := attributenums[a]
	ai.multi = true
	attributenums[a] = ai
	return a
}

func (a Attribute) IsNonUnique() bool {
	ai := attributenums[a]
	return ai.nonunique
}

func (a Attribute) NonUnique() Attribute {
	ai := attributenums[a]
	ai.nonunique = true
	attributenums[a] = ai
	return a
}

var ErrDontMerge = errors.New("Dont merge objects using any methods")
var ErrMergeOnOtherAttr = errors.New("Merge on other attribute")
var ErrMergeOnThis = errors.New("Merge on this attribute")

type mergefunc func(attr Attribute, a, b *Object) (*Object, error)

func StandardMerge(attr Attribute, a, b *Object) (*Object, error) {
	return nil, nil
}

func (a Attribute) Merge(mf mergefunc) Attribute {
	ai := attributenums[a]
	ai.merge = true
	if mf != nil {
		if ai.mf != nil {
			log.Fatal().Msgf("Attribute %v already has a merge function", a)
		}
		ai.mf = mf
	}
	attributenums[a] = ai
	return a
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
