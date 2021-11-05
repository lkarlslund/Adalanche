package engine

import (
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

var attributenames = make(map[string]Attribute)

type attributeinfo struct {
	name   string
	tags   []string
	multi  bool
	unique bool
	merge  bool
}

var attributenums []attributeinfo

var attributepopularity []int
var attributesizes []int

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

	IPAddress          = NewAttribute("IPAddress")
	Hostname           = NewAttribute("Hostname").Merge()
	DownLevelLogonName = NewAttribute("DownLevelLogonName").Merge()
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
		attributepopularity[attribute]++
		attributemutex.RUnlock()
		return attribute
	}
	attributemutex.RUnlock()
	attributemutex.Lock()
	// Retry, someone might have beaten us to it
	if attribute, found := attributenames[lowername]; found {
		attributepopularity[attribute]++
		attributemutex.Unlock()
		return attribute
	}

	newindex := Attribute(len(attributenames))
	attributenames[lowername] = newindex
	attributenums = append(attributenums, attributeinfo{name: name})
	attributepopularity = append(attributepopularity, 1)
	attributesizes = append(attributesizes, 0)
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

func (a Attribute) Unique() Attribute {
	ai := attributenums[a]
	ai.unique = true
	attributenums[a] = ai
	return a
}

func (a Attribute) Merge() Attribute {
	ai := attributenums[a]
	ai.merge = true
	attributenums[a] = ai
	return a
}

func (a Attribute) Tag(t string) Attribute {
	ai := attributenums[a]
	ai.tags = append(ai.tags, t)
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
