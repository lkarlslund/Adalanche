package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/OneOfOne/xxhash"
	"github.com/gofrs/uuid"
	"github.com/icza/gox/stringsx"
	jsoniter "github.com/json-iterator/go"
	"github.com/rs/zerolog/log"
)

//go:generate enumer -type=ObjectType -trimprefix=ObjectType -json

type ObjectType byte

const (
	_ ObjectType = iota
	ObjectTypeOther
	ObjectTypeAttributeSchema
	ObjectTypeGroup
	ObjectTypeForeignSecurityPrincipal
	ObjectTypeUser
	ObjectTypeComputer
	ObjectTypeManagedServiceAccount
	ObjectTypeOrganizationalUnit
	ObjectTypeContainer
	ObjectTypeGroupPolicyContainer
	ObjectTypeTrust
	OBJECTTYPEMAX = ObjectTypeTrust
)

type Object struct {
	DistinguishedName string
	Attributes        map[Attribute][]string

	PwnableBy PwnSet
	CanPwn    PwnSet
	reach     int // AD ControlPower Measurement
	value     int // This objects value

	objecttype       ObjectType
	objectclassguids []uuid.UUID
	objecttypeguid   uuid.UUID

	sidcached bool
	sid       SID

	guidcached bool
	guid       uuid.UUID

	memberofinit bool
	memberof     []*Object
	members      []*Object

	sdcache *SecurityDescriptor
}

type Connection struct {
	Means  string
	Target *Object
}

func NewObject() *Object {
	var result Object
	result.init()
	return &result
}

func (o Object) MarshalJSON() ([]byte, error) {
	// result := make(map[string][]string)
	// for attr, values := range o.Attributes {
	// 	result[attr.Name()] = values
	// }
	return jsoniter.ConfigCompatibleWithStandardLibrary.Marshal(&o.Attributes)
}

func (o Object) DN() string {
	if o.DistinguishedName == "" {
		// !?!?
		dn, found := o.Attributes[DistinguishedName]
		if !found {
			log.Fatal().Msgf("Object has no distinguishedName!?")
		}
		if len(dn) != 1 {
			log.Fatal().Msgf("Attribute distinguishedName does not have a value count of 1")
		}
		return dn[0]
	}
	return o.DistinguishedName
}

func (o Object) Label() string {
	return Default(
		o.OneAttr(LDAPDisplayName),
		o.OneAttr(DisplayName),
		o.OneAttr(Name),
		o.OneAttr(SAMAccountName),
		o.OneAttr(ObjectGUID),
	)
}

func (o Object) ParentDN() string {
	firstcomma := strings.Index(o.DN(), ",")
	if firstcomma >= 0 {
		return o.DN()[firstcomma+1:]
	}
	return ""
}

func (o Object) Type() ObjectType {
	if o.objecttype > 0 {
		return o.objecttype
	}

	category := o.OneAttrRendered(ObjectCategory)

	switch category {
	case "Person":
		o.objecttype = ObjectTypeUser
	case "Group":
		o.objecttype = ObjectTypeGroup
	case "Foreign-Security-Principal":
		o.objecttype = ObjectTypeForeignSecurityPrincipal
	case "ms-DS-Group-Managed-Service-Account":
		o.objecttype = ObjectTypeManagedServiceAccount
	case "Organizational-Unit":
		o.objecttype = ObjectTypeOrganizationalUnit
	case "Container":
		o.objecttype = ObjectTypeContainer
	case "Computer":
		o.objecttype = ObjectTypeComputer
	case "Group-Policy-Container":
		o.objecttype = ObjectTypeGroupPolicyContainer
	case "Domain Trust":
		o.objecttype = ObjectTypeTrust
	case "Attribute-Schema":
		o.objecttype = ObjectTypeAttributeSchema
	default:
		o.objecttype = ObjectTypeOther
	}
	return o.objecttype
}

func (o *Object) ObjectClassGUIDs() []uuid.UUID {
	if len(o.objectclassguids) == 0 {
		for _, class := range o.Attr(ObjectClass) {
			if oto, found := AllObjects.FindClass(class); found {
				var err error
				classguid := oto.OneAttr(SchemaIDGUID)
				og, err := uuid.FromBytes([]byte(classguid))
				if err != nil {
					log.Debug().Msgf("%v", oto)
					log.Fatal().Msgf("Sorry, could not translate SchemaIDGUID for class %v", class)
				} else {
					og = SwapUUIDEndianess(og)
					o.objectclassguids = append(o.objectclassguids, og)
				}
			} else {
				log.Fatal().Msgf("Sorry, could not resolve object class %v, perhaps you didn't get a dump of the schema?", class)
			}
		}
	}
	return o.objectclassguids
}

func (o *Object) ObjectTypeGUID() uuid.UUID {
	if o.objecttypeguid == NullGUID {
		typedn := o.OneAttr(ObjectCategory)
		if typedn == "" {
			// log.Warn().Msgf("Sorry, could not resolve object category %v for object %v, perhaps you didn't get a dump of the schema?", typedn, o.DN())
			// return NullGUID
			return UnknownGUID
		}
		if oto, found := AllObjects.Find(typedn); found {
			var err error
			classguid := oto.OneAttr(SchemaIDGUID)
			o.objecttypeguid, err = uuid.FromBytes([]byte(classguid))
			if err != nil {
				log.Debug().Msgf("%v", oto)
				log.Fatal().Msgf("Sorry, could not translate SchemaIDGUID for %v", typedn)

			}
		} else {
			log.Fatal().Msgf("Sorry, could not resolve object category %v, perhaps you didn't get a dump of the schema?", typedn)
		}
	}
	return o.objecttypeguid
}

func (o Object) Attr(attr Attribute) []string {
	r := o.Attributes[attr]
	if len(r) == 0 && attr == DistinguishedName {
		return []string{o.DN()}
	}
	return r
}

func (o Object) OneAttr(attr Attribute) string {
	a := o.Attr(attr)
	if len(a) == 1 {
		return a[0]
	}
	return ""
}

func (o Object) AttrRendered(attr Attribute) []string {
	values := o.Attr(attr)
	renderedvalues := make([]string, len(values))
	copy(renderedvalues, values)
	switch attr {
	case ObjectSid:
		for i, value := range values {
			renderedvalues[i] = SID(value).String()
		}
	case ObjectCategory:
		for i, value := range values {
			firstcomma := strings.Index(value, ",")
			if firstcomma > 3 {
				renderedvalues[i] = value[3:firstcomma]
			}
		}
	default:
		return values
	}
	return renderedvalues
}

func (o Object) OneAttrRendered(attr Attribute) string {
	a := o.AttrRendered(attr)
	if len(a) == 1 {
		return a[0]
	}
	return ""
}

func (o Object) HasAttrValue(attr Attribute, hasvalue string) bool {
	for _, value := range o.Attr(attr) {
		if value == hasvalue {
			return true
		}
	}
	return false
}

func (o Object) AttrInt(attr Attribute) (int64, bool) {
	value := o.OneAttr(attr)
	v, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func (o Object) AttrTimestamp(attr Attribute) (time.Time, bool) {
	v, ok := o.AttrInt(attr)
	if !ok {
		value := o.OneAttr(attr)
		if strings.HasSuffix(value, "Z") { // "20171111074031.0Z"
			value = strings.TrimSuffix(value, "Z")  // strip "Z"
			value = strings.TrimSuffix(value, ".0") // strip ".0"
			t, err := time.Parse("20060102150405", value)
			return t, err == nil
		}
		return time.Time{}, false
	}
	t := FiletimeToTime(uint64(v))
	// log.Debug().Msgf("Converted %v to %v", v, t)
	return t, true
}

func (o *Object) imamemberofyou(member *Object) {
	o.members = append(o.members, member)
}

func (o *Object) Members(recursive bool) []*Object {
	if !recursive {
		return o.members
	}
	var members map[*Object]struct{}
	for _, directmember := range o.members {
		members[directmember] = struct{}{}
		if recursive {
			for _, indirectmember := range directmember.Members(true) {
				members[indirectmember] = struct{}{}
			}
		}
	}
	membersarray := make([]*Object, len(members))
	var i int
	for member, _ := range members {
		membersarray[i] = member
		i++
	}
	return membersarray
}

func (o *Object) MemberOf() []*Object {
	if !o.memberofinit {
		primaryGroupID := o.OneAttr(PrimaryGroupID)
		if primaryGroupID != "" {
			sid := o.SID()
			if len(sid) > 8 {
				rid, err := strconv.ParseInt(primaryGroupID, 10, 32)
				if err == nil {
					sidbytes := []byte(sid)
					binary.LittleEndian.PutUint32(sidbytes[len(sid)-4:], uint32(rid))
					primarygroup := AllObjects.FindOrAddSID(SID(sidbytes))
					primarygroup.imamemberofyou(o)
					o.memberof = append(o.memberof, primarygroup)
				}
			}
		}

		for _, memberof := range o.Attr(MemberOf) {
			target, found := AllObjects.Find(memberof)
			if !found {
				target = &Object{
					DistinguishedName: memberof,
					Attributes: map[Attribute][]string{
						DistinguishedName: {memberof},
						ObjectCategory:    {"CN=Group,CN=Schema,CN=Configuration," + AllObjects.Base},
						ObjectClass:       {"top", "group"},
						Name:              {"Synthetic group " + memberof},
						Description:       {"Synthetic group"}},
				}
				log.Warn().Msgf("Possible hardening? %v is a member of %v, which is not found - adding synthetic group", o.DN(), memberof)
				AllObjects.Add(target)
			}
			target.imamemberofyou(o)
			o.memberof = append(o.memberof, target)

			if target.SID().RID() == 525 { // "Protected Users"
				o.SetAttr(MetaProtectedUser, "1")
			}
		}
		o.memberofinit = true
	}
	return o.memberof
}

func (o *Object) SetAttr(a Attribute, value string) {
	o.Attributes[a] = []string{value}
}

func (o *Object) Meta() map[string]string {
	result := make(map[string]string)
	for attr, value := range o.Attributes {
		if attr.String()[0] == '_' {
			result[attr.String()] = value[0]
		}
	}
	return result
}

/*func (o Object) Save(filename string) error {
	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, data, 0600)
	return err
}

func (o *Object) Load(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	o.init() // clear data
	err = json.Unmarshal(data, o)
	return err
}*/

func (o *Object) init() {
	o.DistinguishedName = ""
	o.Attributes = make(map[Attribute][]string)
}

func (o *Object) String() string {
	var result string
	result += "OBJECT " + o.DN() + "\n"
	for attr, values := range o.Attributes {
		if attr == NTSecurityDescriptor {
			continue
		}
		result += "  " + attributenums[attr] + ":\n"
		for _, value := range values {
			cleanval := stringsx.Clean(value)
			if cleanval != value {
				result += fmt.Sprintf("    %v (%v original, %v cleaned)\n", value, len(value), len(cleanval))
			} else {
				result += "    " + value + "\n"
			}
		}
	}

	sd, err := o.SecurityDescriptor()
	if err == nil {
		result += "----- SECURITY DESCRIPTOR DUMP -----\n"
		result += sd.String()
	}
	result += "---------------\n"
	return result
}

func (o *Object) SecurityDescriptor() (*SecurityDescriptor, error) {
	if o.sdcache == nil {
		return nil, errors.New("No security desciptor")
	}
	return o.sdcache, nil
}

func (o *Object) cacheSecurityDescriptor(rawsd []byte) error {
	if len(rawsd) == 0 {
		return errors.New("Empty nTSecurityDescriptor attribute!?")
	}

	cacheindex := xxhash.Checksum32(rawsd)
	if sd, found := SecurityDescriptorCache[cacheindex]; found {
		o.sdcache = sd
		return nil
	}

	sd, err := ParseSecurityDescriptor([]byte(rawsd))
	if err == nil {
		o.sdcache = &sd
		SecurityDescriptorCache[cacheindex] = &sd
	}
	return err
}

func (o *Object) Value() int {
	// We cache this, as it's heavy to calculate (0 = not calulated, -1 = cached zero value, otherwise the power factor)
	if o.value != 0 {
		if o.value == -1 {
			return 0
		}
		return o.value
	}
	var value int

	// My own value
	if o.HasAttrValue(ObjectClass, "computer") && o.OneAttr(PrimaryGroupID) == "516" {
		// Domain Controller
		value += 100
	} else if o.HasAttrValue(ObjectClass, "computer") {
		value += 1
	} else if o.HasAttrValue(ObjectClass, "user") {
		value += 1
	}

	targets := make(map[*Object]struct{})
	for _, cp := range o.CanPwn {
		targets[cp.Target] = struct{}{}
	}

	for target := range targets {
		value += target.Value()
	}

	if value == 0 {
		o.value = -1
	} else {
		o.value = value
	}
	return value
}

func (o *Object) SID() SID {
	if !o.sidcached {
		o.sidcached = true
		var err error
		rawsid := o.OneAttr(ObjectSid)
		if rawsid != "" {
			o.sid, _, err = ParseSID([]byte(rawsid))
			if err != nil {
				log.Fatal().Msgf("Could not parse SID %0x: %v", []byte(rawsid), err)
			}
		}
	}
	return o.sid
}

func (o *Object) GUID() uuid.UUID {
	if !o.guidcached {
		rawguid := o.OneAttr(ObjectGUID)
		o.guid = uuid.FromBytesOrNil([]byte(rawguid))
		o.guidcached = true
	}
	return o.guid
}

/*
func (o *Object) Dedup() {
	o.DistinguishedName = stringdedup.S(o.DistinguishedName)
	for key, values := range o.Attributes {
		if key >= MAX_DEDUP {
			continue
		}
		for index, str := range values {
			if len(str) < 64 {
				values[index] = stringdedup.S(str)
			}
		}
		o.Attributes[key] = values
	}
}
*/
