package engine

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OneOfOne/xxhash"
	"github.com/gofrs/uuid"
	"github.com/icza/gox/stringsx"
	jsoniter "github.com/json-iterator/go"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/lkarlslund/stringdedup"
	"github.com/rs/zerolog/log"
)

//go:generate enumer -type=ObjectType -trimprefix=ObjectType -json

var threadsafeobject int

const threadbuckets = 1024

var threadsafeobjectmutexes [threadbuckets]sync.RWMutex

func SetThreadsafe(enable bool) {
	if enable {
		threadsafeobject++
	} else {
		threadsafeobject--
	}
	if threadsafeobject < 0 {
		panic("threadsafeobject is negative")
	}
}

type ObjectType byte

var UnknownGUID = uuid.UUID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

const (
	_ ObjectType = iota
	ObjectTypeOther
	ObjectTypeAttributeSchema
	ObjectTypeClassSchema
	ObjectTypeControlAccessRight
	ObjectTypeGroup
	ObjectTypeForeignSecurityPrincipal
	ObjectTypeDomainDNS
	ObjectTypeDNSNode
	ObjectTypeDNSZone
	ObjectTypeUser
	ObjectTypeComputer
	ObjectTypeManagedServiceAccount
	ObjectTypeOrganizationalUnit
	ObjectTypeContainer
	ObjectTypeGroupPolicyContainer
	ObjectTypeCertificateTemplate
	ObjectTypeTrust
	ObjectTypeService
	ObjectTypeExecutable
	OBJECTTYPEMAX = iota - 1
)

type Object struct {
	id uint32 // Unique ID in Objects collection

	AttributeValueMap

	PwnableBy PwnConnections
	CanPwn    PwnConnections

	parent   *Object
	children []*Object

	// reach     int // AD ControlPower Measurement
	// value     int // This objects value

	objecttype         ObjectType
	objectclassguids   []uuid.UUID
	objectcategoryguid uuid.UUID

	sidcached bool
	sid       windowssecurity.SID

	guidcached bool
	guid       uuid.UUID

	memberof []*Object
	members  []*Object

	sdcache *SecurityDescriptor
}

type Connection struct {
	Means  string
	Target *Object
}

var IgnoreBlanks = "_IGNOREBLANKS_"

func NewObject(flexinit ...interface{}) *Object {
	var result Object
	result.init()
	result.Set(flexinit...)

	return &result
}

func (o *Object) ID() uint32 {
	if o.id == 0 {
		panic("no ID set on object, where did it come from?")
	}
	return o.id
}

func (o *Object) lockbucket() int {
	return int(o.ID()) % threadbuckets
}

func (o *Object) lock() {
	if threadsafeobject != 0 {
		threadsafeobjectmutexes[o.lockbucket()].Lock()
	}
}

func (o *Object) rlock() {
	if threadsafeobject != 0 {
		threadsafeobjectmutexes[o.lockbucket()].RLock()
	}
}

func (o *Object) unlock() {
	if threadsafeobject != 0 {
		threadsafeobjectmutexes[o.lockbucket()].Unlock()
	}
}

func (o *Object) runlock() {
	if threadsafeobject != 0 {
		threadsafeobjectmutexes[o.lockbucket()].RUnlock()
	}
}

// Absorbs data and Pwn relationships from another object, sucking the soul out of it
// The sources empty shell should be discarded afterwards (i.e. not appear in an Objects collection)
func (o *Object) Absorb(source *Object) {
	o.lock()
	source.lock()
	defer source.unlock()
	defer o.unlock()

	target := o
	for attr, values := range source.AttributeValueMap {
		var val AttributeValues
		tval := target.Attr(attr)
		sval := values
		tvalslice := tval.Slice()
		svalslice := sval.Slice()

		if len(tvalslice) == 0 {
			val = sval
		} else if len(svalslice) == 0 {
			panic(fmt.Sprintf("Attribute %v with ZERO LENGTH data failure", attr.String()))
		} else if len(tvalslice) == 1 && len(svalslice) == 1 {
			if CompareAttributeValues(tvalslice[0], svalslice[0]) {
				val = tval // They're the same, so pick any
			} else {
				// They're not the same, join them
				val = AttributeValueSlice{tvalslice[0], svalslice[0]}
			}
		} else {
			// One or more of them have more than one value, do it the hard way
			resultingvalues := make([]AttributeValue, len(svalslice))
			copy(resultingvalues, tvalslice)
			for _, svalue := range svalslice {
				var alreadythere bool
			compareloop:
				for _, tvalue := range tvalslice {
					if CompareAttributeValues(svalue, tvalue) { // Crap!!
						alreadythere = true
						break compareloop
					}
				}
				if !alreadythere {
					resultingvalues = append(resultingvalues, svalue)
				}
			}
			val = AttributeValueSlice(resultingvalues)
		}
		target.AttributeValueMap[attr] = val
	}

	for pwntarget, methods := range source.CanPwn {
		target.CanPwn[pwntarget] = target.CanPwn[pwntarget].Merge(methods)
		delete(source.CanPwn, pwntarget)
		pwntarget.PwnableBy[target] = pwntarget.PwnableBy[target].Merge(methods)
		delete(pwntarget.PwnableBy, source)
	}

	for pwner, methods := range source.PwnableBy {
		target.PwnableBy[pwner] = target.PwnableBy[pwner].Merge(methods)
		delete(source.PwnableBy, pwner)
		pwner.CanPwn[target] = pwner.CanPwn[target].Merge(methods)
		delete(pwner.CanPwn, source)
	}

	members := make(map[*Object]struct{})
	for _, member := range target.members {
		members[member] = struct{}{}
	}
	for _, newmember := range source.members {
		if _, found := members[newmember]; !found {
			target.members = append(target.members, newmember)
		}
	}

	memberofgroups := make(map[*Object]struct{})
	for _, memberof := range target.memberof {
		memberofgroups[memberof] = struct{}{}
	}
	for _, newmemberof := range source.memberof {
		if _, found := memberofgroups[newmemberof]; !found {
			target.memberof = append(target.memberof, newmemberof)
		}
	}

	for _, child := range source.children {
		target.Adopt(child)
	}

	// Move the securitydescriptor, as we dont have the attribute saved to regenerate it (we throw it away at import after populating the cache)
	if target.sdcache == nil && source.sdcache != nil {
		target.sdcache = source.sdcache
	}

	// If the source has a parent, but the target doesn't we assimilate that role (muhahaha)
	if target.parent == nil && source.parent != nil {
		source.parent.RemoveChild(source)
		target.ChildOf(source.parent)
	}

	target.objecttype = 0 // Recalculate this
}

func (o *Object) MarshalJSON() ([]byte, error) {
	return jsoniter.ConfigCompatibleWithStandardLibrary.Marshal(&o.AttributeValueMap)
}

func (o *Object) IDString() string {
	return strconv.FormatUint(uint64(o.ID()), 10)
}

func (o *Object) DN() string {
	return o.OneAttrString(DistinguishedName)
}

func (o *Object) Label() string {
	return util.Default(
		o.OneAttrString(LDAPDisplayName),
		o.OneAttrString(DisplayName),
		o.OneAttrString(Name),
		o.OneAttrString(DownLevelLogonName),
		o.OneAttrString(SAMAccountName),
		o.OneAttrString(Description),
		o.OneAttrString(DistinguishedName),
		o.OneAttrString(ObjectGUID),
		o.OneAttrString(ObjectSid),
	)
}

func (o *Object) Type() ObjectType {
	if o.objecttype > 0 {
		return o.objecttype
	}

	category := o.OneAttrString(ObjectCategory)
	if category != "" {
		equalpos := strings.Index(category, "=")
		commapos := strings.Index(category, ",")
		if equalpos == -1 || commapos == -1 || equalpos >= commapos {
			// Just keep it as-is
		} else {
			category = category[equalpos+1 : commapos]
		}
	} else {
		category = o.OneAttrString(ObjectCategorySimple)
	}

	switch category {
	case "Domain-DNS":
		o.objecttype = ObjectTypeDomainDNS
	case "Dns-Node":
		o.objecttype = ObjectTypeDNSNode
	case "Dns-Zone":
		o.objecttype = ObjectTypeDNSZone
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
	case "Class-Schema":
		o.objecttype = ObjectTypeClassSchema
	case "Control-Access-Right":
		o.objecttype = ObjectTypeControlAccessRight
	case "PKI-Certificate-Template":
		o.objecttype = ObjectTypeCertificateTemplate
	case "Service":
		o.objecttype = ObjectTypeService
	case "Executable":
		o.objecttype = ObjectTypeExecutable
	default:
		o.objecttype = ObjectTypeOther
	}
	return o.objecttype
}

func (o *Object) ObjectClassGUIDs() []uuid.UUID {
	if len(o.objectclassguids) == 0 {
	}
	return o.objectclassguids
}

func (o *Object) ObjectCategoryGUID(ao *Objects) uuid.UUID {
	if o.objectcategoryguid == NullGUID {
	}
	return o.objectcategoryguid
}

func (o *Object) AttrString(attr Attribute) []string {
	return o.Attr(attr).StringSlice()
}

func (o *Object) AttrRendered(attr Attribute) []string {
	switch attr {
	case ObjectCategory:
		// ocguid := o.ObjectCategoryGUID()
		// if ocguid != UnknownGUID {
		// 	if schemaobject, found := AllObjects.Find(SchemaIDGUID, AttributeValueGUID(o.ObjectCategoryGUID())); found {
		// 		// fmt.Println(schemaobject)
		// 		return []string{schemaobject.OneAttrString(Name)}
		// 	}
		// }

		cat := o.OneAttrString(ObjectCategory)
		if cat != "" {

			splitted := strings.Split(cat, ",")
			if len(splitted) > 1 {
				// This is a DN pointing to a category - otherwise it's just something we made up! :)
				return []string{splitted[0][3:]}
			}
			return []string{cat}
		}

		return []string{"Unknown"}
	default:
		return o.Attr(attr).StringSlice()
	}
}

func (o *Object) OneAttrRendered(attr Attribute) string {
	r := o.AttrRendered(attr)
	if len(r) == 0 {
		return ""
	}
	return r[0]
}

// Returns synthetic blank attribute value if it isn't set
func (o *Object) Attr(attr Attribute) AttributeValues {
	o.lock()
	defer o.unlock()
	if attrs, found := o.Find(attr); found {
		if attrs == nil {
			panic(fmt.Sprintf("Looked for attribute %v and found NIL value", attr.String()))
		}
		return attrs
	}
	return NoValues{}
}

func (o *Object) OneAttrString(attr Attribute) string {
	a, found := o.Find(attr)
	if !found {
		return ""
	}
	if ao, ok := a.(AttributeValueOne); ok {
		return ao.String()
	}
	if a.Len() == 1 {
		log.Warn().Msg("Inefficient attribute storage - multival used for one value ...")
		return a.Slice()[0].String()
	}
	log.Error().Msgf("Attribute %v lookup for ONE value, but contains %v (%v)", attr.String(), a.Len(), strings.Join(a.StringSlice(), ", "))
	return ""
}

func (o *Object) OneAttrRaw(attr Attribute) interface{} {
	a := o.Attr(attr)
	if a == nil {
		return nil
	}
	if a.Len() == 1 {
		return a.Slice()[0].Raw()
	}
	return nil
}

func (o *Object) OneAttr(attr Attribute) AttributeValue {
	a := o.Attr(attr)
	if a == nil {
		return nil
	}
	if a.Len() == 1 {
		return a.Slice()[0]
	}
	return nil
}

func (o *Object) HasAttr(attr Attribute) bool {
	_, found := o.Find(attr)
	return found
}

func (o *Object) HasAttrValue(attr Attribute, hasvalue AttributeValue) bool {
	for _, value := range o.Attr(attr).Slice() {
		if CompareAttributeValues(value, hasvalue) {
			return true
		}
	}
	return false
}

func (o *Object) AttrInt(attr Attribute) (int64, bool) {
	v, ok := o.OneAttrRaw(attr).(int64)
	return v, ok
}

func (o *Object) AttrTimestamp(attr Attribute) (time.Time, bool) { // FIXME, switch to auto-time formatting
	v, ok := o.AttrInt(attr)
	if !ok {
		value := o.OneAttrString(attr)
		if strings.HasSuffix(value, "Z") { // "20171111074031.0Z"
			value = strings.TrimSuffix(value, "Z")  // strip "Z"
			value = strings.TrimSuffix(value, ".0") // strip ".0"
			t, err := time.Parse("20060102150405", value)
			return t, err == nil
		}
		return time.Time{}, false
	}
	t := util.FiletimeToTime(uint64(v))
	// log.Debug().Msgf("Converted %v to %v", v, t)
	return t, true
}

func (o *Object) AddMember(member *Object) {
	o.lock()
	o.members = append(o.members, member)
	member.memberof = append(member.memberof, o)
	o.unlock()
}

func (o *Object) Members(recursive bool) []*Object {
	o.lock()
	defer o.unlock()
	if !recursive {
		return o.members
	}

	members := make(map[*Object]struct{})
	o.recursemembers(members)

	membersarray := make([]*Object, len(members))
	var i int
	for member := range members {
		membersarray[i] = member
		i++
	}
	return membersarray
}

func (o *Object) recursemembers(members map[*Object]struct{}) {
	for _, directmember := range o.members {
		if _, found := members[directmember]; found {
			// endless loop, not today thanks
			continue
		}
		members[directmember] = struct{}{}
		directmember.recursemembers(members)
	}
}

func (o *Object) MemberOf() []*Object {
	return o.memberof
}

// Wrapper for Set - easier to call
func (o *Object) SetAttr(a Attribute, values ...AttributeValue) {
	if values == nil {
		panic(fmt.Sprintf("tried to set attribute %v to NIL value", a.String()))
	}
	if len(values) == 0 {
		panic(fmt.Sprintf("tried to set attribute %v to NO values", a.String()))
	}
	o.Set(a, AttributeValueSlice(values))
}

func (o *Object) Set(flexinit ...interface{}) {
	var ignoreblanks bool

	o.lock()
	defer o.unlock()

	var attribute Attribute
	data := make(AttributeValueSlice, 0, 1)
	for _, i := range flexinit {
		if i == IgnoreBlanks {
			ignoreblanks = true
			continue
		}
		switch v := i.(type) {
		case Attribute:
			if attribute != 0 && (!ignoreblanks || len(data) > 0) {
				o.set(attribute, data)
			}
			data = make(AttributeValueSlice, 0, 1)
			attribute = v
		case AttributeValue:
			if v == nil {
				panic("This is impossble")
			}
			if v.String() == "" && ignoreblanks {
				continue
			}
			data = append(data, v)
		case AttributeValueSlice:
			for _, value := range v.Slice() {
				if value == nil {
					panic("Inserting NIL is not supported")
				}
				if ignoreblanks && value.String() == "" {
					continue
				}
				data = append(data, value)
			}
		case NoValues:
			// Ignore it
		default:
			panic("Invalid type in object declaration")
		}
	}
	if attribute != 0 && (!ignoreblanks || len(data) > 0) {
		o.set(attribute, data)
	}
}

func (o *Object) set(a Attribute, values AttributeValues) {
	if a == DownLevelLogonName {
		if values.Len() != 1 {
			panic("Only one!")
		}
		if strings.HasSuffix(values.StringSlice()[0], "\\") {
			panic("DownLevelLogon ends with \\")
		}
	}
	if a == NTSecurityDescriptor {
		for _, sd := range values.Slice() {
			if err := o.cacheSecurityDescriptor([]byte(sd.Raw().(string))); err != nil {
				log.Error().Msgf("Problem parsing security descriptor for %v: %v", o.DN(), err)
			}
		}
		return // We dont store the raw version, just the decoded one, KTHX
	}

	// Deduplication of strings
	valueslice := values.Slice()
	for i, value := range valueslice {
		if avs, ok := value.(AttributeValueString); ok {
			valueslice[i] = AttributeValueString(stringdedup.S(string(avs)))
		}
	}

	o.AttributeValueMap.Set(a, AttributeValueSlice(valueslice))

	// Statistics
	for _, value := range values.StringSlice() {
		attributesizes[a] += len(value)
	}
}

func (o *Object) Meta() map[string]string {
	result := make(map[string]string)
	for attr, value := range o.AttributeValueMap {
		if attr.String()[0] == '_' {
			result[attr.String()] = value.Slice()[0].String()
		}
	}
	return result
}

func (o *Object) init() {
	o.id = atomic.AddUint32(&idcounter, 1)
	if o.AttributeValueMap == nil {
		o.AttributeValueMap = make(AttributeValueMap)
	}
	if o.CanPwn == nil || o.PwnableBy == nil {
		o.CanPwn = make(PwnConnections)
		o.PwnableBy = make(PwnConnections)
	}
}

func (o *Object) String(ao *Objects) string {
	var result string
	result += "OBJECT " + o.DN() + "\n"
	for attr, values := range o.AttributeValueMap {
		if attr == NTSecurityDescriptor {
			continue
		}
		result += "  " + attributenums[attr].name + ":\n"
		for _, value := range values.Slice() {
			cleanval := stringsx.Clean(value.String())
			if cleanval != value.String() {
				result += fmt.Sprintf("    %v (%v original, %v cleaned)\n", value, len(value.String()), len(cleanval))
			} else {
				result += "    " + value.String() + "\n"
			}
		}

		if an, ok := values.(AttributeNode); ok {
			// dump with recursion - fixme
			an.Children()
		}
	}

	sd, err := o.SecurityDescriptor()
	if err == nil {
		result += "----- SECURITY DESCRIPTOR DUMP -----\n"
		result += sd.String(ao)
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

	securitydescriptorcachemutex.RLock()
	cacheindex := xxhash.Checksum32(rawsd)
	if sd, found := securityDescriptorCache[cacheindex]; found {
		securitydescriptorcachemutex.RUnlock()
		o.sdcache = sd
		return nil
	}
	securitydescriptorcachemutex.RUnlock()

	securitydescriptorcachemutex.Lock()
	sd, err := ParseSecurityDescriptor([]byte(rawsd))
	if err == nil {
		o.sdcache = &sd
		securityDescriptorCache[cacheindex] = &sd
	}
	securitydescriptorcachemutex.Unlock()
	return err
}

func (o *Object) SID() windowssecurity.SID {
	if !o.sidcached {
		o.sidcached = true
		if sid, ok := o.OneAttrRaw(ObjectSid).(windowssecurity.SID); ok {
			o.sid = sid
		}
	}
	return o.sid
}

func (o *Object) GUID() uuid.UUID {
	if !o.guidcached {
		if guid, ok := o.OneAttrRaw(ObjectGUID).(uuid.UUID); ok {
			o.guid = guid
		}
		o.guidcached = true
	}
	return o.guid
}

func (o *Object) Pwns(target *Object, method PwnMethod) {
	if o == target { // SID check solves (some) dual-AD analysis problems
		// We don't care about self owns
		return
	}

	if o.SID() != windowssecurity.BlankSID && o.SID() == target.SID() {
		return
	}

	// Ignore these, SELF = self own, Creator/Owner always has full rights
	if o.SID() == windowssecurity.SelfSID || o.SID() == windowssecurity.SystemSID {
		return
	}

	o.lock()
	o.CanPwn.Set(target, method) // Add the connection
	o.unlock()
	target.lock()
	target.PwnableBy.Set(o, method) // Add the reverse connection too
	target.unlock()
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

func (o *Object) ChildOf(parent *Object) {
	o.lock()
	if o.parent != nil {
		log.Debug().Msgf("Object already %v has %v as parent, so I'm not assigning %v as parent", o.Label(), o.parent.Label(), parent.Label())
		// panic("objects can only have one parent")
	}
	o.parent = parent
	o.unlock()
	parent.lock()
	parent.children = append(parent.children, o)
	parent.unlock()
}

func (o *Object) Adopt(child *Object) {
	o.lock()
	o.children = append(o.children, child)
	o.unlock()

	child.lock()
	if child.parent != nil {
		child.parent.RemoveChild(child)
	}
	child.parent = o
	child.unlock()
}

func (o *Object) RemoveChild(child *Object) {
	for i, curchild := range o.children {
		if curchild == child {
			if i < len(o.children)+1 {
				// Not the last one, move things
				copy(o.children[i:], o.children[i+1:])
			}
			// Remove last item
			o.children = o.children[:len(o.children)-1]
			return
		}
	}
	panic("tried to remove a child not related to parent")
}

func (o *Object) Parent() *Object {
	o.rlock()
	defer o.runlock()
	return o.parent
}

func (o *Object) Children() []*Object {
	o.rlock()
	defer o.runlock()
	return o.children
}
