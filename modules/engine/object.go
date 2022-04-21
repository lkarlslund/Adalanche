package engine

import (
	"encoding/xml"
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

var threadsafeobject int

const threadbuckets = 1024

var threadsafeobjectmutexes [threadbuckets]sync.RWMutex

func init() {
	stringdedup.YesIKnowThisCouldGoHorriblyWrong = true
}

func setThreadsafe(enable bool) {
	if enable {
		threadsafeobject++
	} else {
		threadsafeobject--
	}
	if threadsafeobject < 0 {
		panic("threadsafeobject is negative")
	}
}

var UnknownGUID = uuid.UUID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type Object struct {
	values           AttributeValueMap
	PwnableBy        PwnConnections
	CanPwn           PwnConnections
	parent           *Object
	sdcache          *SecurityDescriptor
	sid              windowssecurity.SID
	children         []*Object
	members          []*Object
	membersrecursive []*Object

	memberof          []*Object
	memberofrecursive []*Object

	memberofsid          []windowssecurity.SID
	memberofsidrecursive []windowssecurity.SID

	id   uint32
	guid uuid.UUID
	// objectcategoryguid uuid.UUID
	guidcached bool
	sidcached  bool
	objecttype ObjectType
}

type Connection struct {
	Target *Object
	Means  string
}

var IgnoreBlanks = "_IGNOREBLANKS_"

func NewObject(flexinit ...interface{}) *Object {
	var result Object
	result.init()
	result.setFlex(flexinit...)

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
	if source.lockbucket() != o.lockbucket() {
		source.lock()
		defer source.unlock()
	}
	defer o.unlock()

	target := o
	for attr, values := range source.values {
		var val AttributeValues
		tval := target.attr(attr)
		sval := values

		if tval.Len() == 0 {
			val = sval
		} else if sval.Len() == 0 {
			panic(fmt.Sprintf("Attribute %v with ZERO LENGTH data failure", attr.String()))
		} else if tval.Len() == 1 && sval.Len() == 1 {
			tvalue := tval.Slice()[0]
			svalue := sval.Slice()[0]

			if CompareAttributeValues(tvalue, svalue) {
				val = tval // They're the same, so pick any
			} else {
				// They're not the same, join them
				val = AttributeValueSlice{tvalue, svalue}
			}
		} else {
			// One or more of them have more than one value, do it the hard way
			tvalslice := tval.Slice()
			svalslice := sval.Slice()

			resultingvalues := make([]AttributeValue, tval.Len())
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
		target.set(attr, val)
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

	if len(source.members) > 0 {
		members := make(map[*Object]struct{})
		for _, member := range target.members {
			members[member] = struct{}{}

			member.memberofrecursive = nil
			member.membersrecursive = nil
		}

		for _, newmember := range source.members {
			if _, found := members[newmember]; !found {
				target.members = append(target.members, newmember)

				newmember.memberofrecursive = nil
				newmember.membersrecursive = nil
			}
		}
		source.members = nil
		source.membersrecursive = nil
	} else {
		target.members = source.members
	}

	if len(source.memberof) > 0 {
		memberofgroups := make(map[*Object]struct{})
		for _, memberof := range target.memberof {
			memberofgroups[memberof] = struct{}{}
		}
		for _, newmemberof := range source.memberof {
			if _, found := memberofgroups[newmemberof]; !found {
				target.memberof = append(target.memberof, newmemberof)
			}
		}
		source.memberof = nil
		source.memberofrecursive = nil
	} else {
		target.memberof = source.memberof
	}

	for _, child := range source.children {
		target.Adopt(child)
	}

	// Move the securitydescriptor, as we dont have the attribute saved to regenerate it (we throw it away at import after populating the cache)
	if target.sdcache == nil && source.sdcache != nil {
		target.sdcache = source.sdcache
	} else {
		target.sdcache = nil
	}

	// If the source has a parent, but the target doesn't we assimilate that role (muhahaha)
	if target.parent == nil && source.parent != nil {
		source.parent.RemoveChild(source)
		target.ChildOf(source.parent)
	}

	target.objecttype = 0 // Recalculate this

	target.memberofrecursive = nil // Clear cache
	target.membersrecursive = nil  // Clear cache

	target.memberofsid = nil          // Clear cache
	target.memberofsidrecursive = nil // Clear cache
}

func (o *Object) AttributeValueMap() AttributeValueMap {
	o.lock()
	defer o.unlock()
	val := o.values
	for attr, _ := range val {
		if attributenums[attr].onget != nil {
			val[attr], _ = attributenums[attr].onget(o, attr)
		}
	}
	return val
}

type StringMap map[string][]string

func (s StringMap) MarshalXML(e *xml.Encoder, start xml.StartElement) error {

	tokens := []xml.Token{start}

	for key, values := range s {
		t := xml.StartElement{Name: xml.Name{"", key}}
		for _, value := range values {
			tokens = append(tokens, t, xml.CharData(value), xml.EndElement{t.Name})
		}
	}

	tokens = append(tokens, xml.EndElement{start.Name})

	for _, t := range tokens {
		err := e.EncodeToken(t)
		if err != nil {
			return err
		}
	}

	// flush to ensure tokens are written
	return e.Flush()
}

func (o *Object) NameStringMap() StringMap {
	o.lock()
	defer o.unlock()
	result := make(StringMap)
	for attr, values := range o.values {
		result[attr.String()] = values.StringSlice()
	}
	return result
}

func (o *Object) MarshalJSON() ([]byte, error) {
	return jsoniter.ConfigCompatibleWithStandardLibrary.Marshal(o.NameStringMap())
}

func (o *Object) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return o.NameStringMap().MarshalXML(e, start)
}

func (o *Object) IDString() string {
	return strconv.FormatUint(uint64(o.ID()), 10)
}

func (o *Object) DN() string {
	return o.OneAttrString(DistinguishedName)
}

var labelattrs = []Attribute{
	LDAPDisplayName,
	DisplayName,
	Name,
	DownLevelLogonName,
	SAMAccountName,
	Description,
	DistinguishedName,
	ObjectGUID,
	ObjectSid,
}

func (o *Object) Label() string {
	for _, attr := range labelattrs {
		val := o.OneAttrString(attr)
		if val != "" {
			return val
		}
	}
	return fmt.Sprintf("OBJ %v", o)
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

	objecttype, found := ObjectTypeLookup(category)
	if found {
		o.objecttype = objecttype
	}
	return objecttype
}

func (o *Object) ObjectCategoryGUID(ao *Objects) uuid.UUID {
	// if o.objectcategoryguid == NullGUID {
	guid := o.OneAttrRaw(ObjectCategoryGUID)
	if guid == nil {
		return UnknownGUID
	}
	return guid.(uuid.UUID)
	// return o.objectcategoryguid
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
func (o *Object) get(attr Attribute) (AttributeValues, bool) {
	if attributenums[attr].onget != nil {
		return attributenums[attr].onget(o, attr)
	}
	return o.values.Get(attr)
}

// Auto locking version
func (o *Object) Get(attr Attribute) (AttributeValues, bool) {
	o.rlock()
	defer o.runlock()
	return o.get(attr)
}

// Returns synthetic blank attribute value if it isn't set
func (o *Object) attr(attr Attribute) AttributeValues {
	if attrs, found := o.get(attr); found {
		if attrs == nil {
			panic(fmt.Sprintf("Looked for attribute %v and found NIL value", attr.String()))
		}
		return attrs
	}
	return NoValues{}
}

// Returns synthetic blank attribute value if it isn't set
func (o *Object) Attr(attr Attribute) AttributeValues {
	o.rlock()
	defer o.runlock()
	return o.attr(attr)
}

func (o *Object) OneAttrString(attr Attribute) string {
	o.rlock()
	defer o.runlock()
	a, found := o.get(attr)
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
	_, found := o.Get(attr)
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
	member.lock()
	for _, mo := range member.memberof {
		// Dupe elimination
		if mo == o {
			member.unlock()
			return
		}
	}
	member.memberof = append(member.memberof, o)
	member.unlock()
	o.lock()
	o.members = append(o.members, member)
	o.unlock()
}

func (o *Object) Members(recursive bool) []*Object {
	o.lock()
	defer o.unlock()
	if !recursive {
		return o.members
	}

	members := make(map[*Object]struct{})
	o.recursemembers(&members)

	membersarray := make([]*Object, len(members))
	var i int
	for member := range members {
		membersarray[i] = member
		i++
	}
	return membersarray
}

func (o *Object) recursemembers(members *map[*Object]struct{}) {
	for _, directmember := range o.members {
		if _, found := (*members)[directmember]; found {
			// endless loop, not today thanks
			continue
		}
		(*members)[directmember] = struct{}{}
		directmember.recursemembers(members)
	}
}

func (o *Object) MemberOf(recursive bool) []*Object {
	o.lock()
	defer o.unlock()
	return o.memberofr(recursive)
}

func (o *Object) memberofr(recursive bool) []*Object {
	if !recursive || len(o.memberof) == 0 {
		return o.memberof
	}

	if o.memberofrecursive != nil {
		return o.memberofrecursive
	}

	memberof := make(map[*Object]struct{})
	o.recursememberof(&memberof)

	memberofarray := make([]*Object, len(memberof))
	var i int
	for member := range memberof {
		memberofarray[i] = member
		i++
	}
	o.memberofrecursive = memberofarray
	return memberofarray
}

// Recursive memberof, returns true if loop is detected
func (o *Object) recursememberof(memberof *map[*Object]struct{}) bool {
	var loop bool
	for _, directmemberof := range o.memberof {
		if _, found := (*memberof)[directmemberof]; found {
			// endless loop, not today thanks
			loop = true
			continue
		}
		(*memberof)[directmemberof] = struct{}{}
		if directmemberof.recursememberof(memberof) {
			loop = true
		}
	}
	return loop
}

func (o *Object) MemberOfSID(recursive bool) []windowssecurity.SID {
	o.lock()
	defer o.unlock()

	if !recursive {
		if o.memberofsid == nil {
			o.memberofsid = make([]windowssecurity.SID, len(o.memberof))
			for i, memberof := range o.memberof {
				o.memberofsid[i] = memberof.SID()
			}
		}

		return o.memberofsid
	}

	if o.memberofsidrecursive != nil {
		return o.memberofsidrecursive
	}

	memberofrecursive := o.memberofr(true)
	o.memberofsidrecursive = make([]windowssecurity.SID, len(memberofrecursive))

	for i, memberof := range memberofrecursive {
		o.memberofsidrecursive[i] = memberof.SID()
	}

	return o.memberofsidrecursive
}

// Wrapper for Set - easier to call
func (o *Object) SetValues(a Attribute, values ...AttributeValue) {
	if values == nil {
		panic(fmt.Sprintf("tried to set attribute %v to NIL value", a.String()))
	}
	if len(values) == 0 {
		panic(fmt.Sprintf("tried to set attribute %v to NO values", a.String()))
	}
	o.Set(a, AttributeValueSlice(values))
}

func (o *Object) SetFlex(flexinit ...interface{}) {
	o.lock()
	o.setFlex(flexinit...)
	o.unlock()
}

var avsPool sync.Pool

func init() {
	avsPool.New = func() interface{} {
		return make(AttributeValueSlice, 0, 16)
	}
}

func (o *Object) setFlex(flexinit ...interface{}) {
	var ignoreblanks bool

	attribute := NonExistingAttribute

	data := avsPool.Get().(AttributeValueSlice)
	for _, i := range flexinit {
		if i == IgnoreBlanks {
			ignoreblanks = true
			continue
		}
		switch v := i.(type) {
		case windowssecurity.SID:
			if ignoreblanks && v.IsNull() {
				continue
			}
			data = append(data, AttributeValueSID(v))
		case *[]string:
			if v == nil {
				continue
			}
			if ignoreblanks && len(*v) == 0 {
				continue
			}
			for _, s := range *v {
				if ignoreblanks && s == "" {
					continue
				}
				data = append(data, AttributeValueString(s))
			}
		case []string:
			if ignoreblanks && len(v) == 0 {
				continue
			}
			for _, s := range v {
				if ignoreblanks && s == "" {
					continue
				}
				data = append(data, AttributeValueString(s))
			}
		case *string:
			if v == nil {
				continue
			}
			if ignoreblanks && len(*v) == 0 {
				continue
			}
			data = append(data, AttributeValueString(*v))
		case string:
			if ignoreblanks && len(v) == 0 {
				continue
			}
			data = append(data, AttributeValueString(v))
		case *time.Time:
			if v == nil {
				continue
			}
			if ignoreblanks && v.IsZero() {
				continue
			}
			data = append(data, AttributeValueTime(*v))
		case time.Time:
			if ignoreblanks && v.IsZero() {
				continue
			}
			data = append(data, AttributeValueTime(v))
		case *bool:
			if v == nil {
				continue
			}
			data = append(data, AttributeValueBool(*v))
		case bool:
			data = append(data, AttributeValueBool(v))
		case int:
			if ignoreblanks && v == 0 {
				continue
			}
			data = append(data, AttributeValueInt(v))
		case int64:
			if ignoreblanks && v == 0 {
				continue
			}
			data = append(data, AttributeValueInt(v))
		case AttributeValue:
			if ignoreblanks && v.IsZero() {
				continue
			}
			data = append(data, v)
		case AttributeValueSlice:
			for _, value := range v {
				if ignoreblanks && value.IsZero() {
					continue
				}
				data = append(data, value)
			}
		case NoValues:
			// Ignore it
		case Attribute:
			if attribute != NonExistingAttribute && (!ignoreblanks || len(data) > 0) {
				newdata := make(AttributeValueSlice, len(data))
				copy(newdata, data)
				o.set(attribute, newdata)

				data = data[:0]
			}
			attribute = v
		default:
			panic("SetFlex called with invalid type in object declaration")
		}
	}
	if attribute != NonExistingAttribute && (!ignoreblanks || len(data) > 0) {
		o.set(attribute, data)
	}
	if len(data) > 0 {
		data = data[:0]
	}
	avsPool.Put(data)
}

func (o *Object) Set(a Attribute, values AttributeValues) {
	o.lock()
	defer o.unlock()
	o.set(a, values)
}

func (o *Object) set(a Attribute, values AttributeValues) {
	if a.IsSingle() && values.Len() > 1 {
		log.Warn().Msgf("Setting multiple values on non-multival attribute %v: %v", a.String(), strings.Join(values.StringSlice(), ", "))
	}

	if a == DownLevelLogonName {
		// There's been so many problems with DLLN that we're going to just check for these
		strval := values.StringSlice()[0]
		if strval == "," {
			log.Warn().Msgf("Setting DownLevelLogonName to ',' is not allowed")
		}
		if strval == "" {
			log.Warn().Msgf("Setting DownLevelLogonName to blank is not allowed")
		}
		if strings.HasPrefix(strval, "S-") {
			log.Warn().Msgf("DownLevelLogonName contains SID: %v", values.StringSlice())
		}
		if values.Len() != 1 {
			log.Warn().Msgf("Found DownLevelLogonName with multiple values: %v", strings.Join(values.StringSlice(), ", "))
		}
		if strings.HasSuffix(strval, "\\") {
			panic("DownLevelLogon ends with \\")
		}
	}

	if a == ObjectCategory || a == ObjectCategorySimple {
		// Clear objecttype cache attribute
		o.objecttype = 0
	}

	// Cache the NTSecurityDescriptor
	if a == NTSecurityDescriptor {
		for _, sd := range values.Slice() {
			if err := o.cacheSecurityDescriptor([]byte(sd.Raw().(string))); err != nil {
				log.Error().Msgf("Problem parsing security descriptor for %v: %v", o.DN(), err)
			}
		}
		return // We dont store the raw version, just the decoded one, KTHX
	}

	// Deduplication of values
	valueslice := values.Slice()
	for i, value := range valueslice {
		switch avs := value.(type) {
		case AttributeValueString:
			valueslice[i] = AttributeValueString(stringdedup.S(string(avs)))
		case AttributeValueBlob:
			valueslice[i] = AttributeValueBlob(stringdedup.B([]byte(avs)))
		}
	}

	var av AttributeValues

	if len(valueslice) == 1 {
		av = AttributeValueOne{valueslice[0]}
	} else {
		av = AttributeValueSlice(valueslice)
	}

	if attributenums[a].onset != nil {
		attributenums[a].onset(o, a, av)
		o.values.Set(a, nil) // placeholder for iteration over attributes that are set
	} else {
		o.values.Set(a, av)
	}
}

func (o *Object) Meta() map[string]string {
	result := make(map[string]string)
	for attr, value := range o.values {
		if attr.String()[0] == '_' {
			result[attr.String()] = value.Slice()[0].String()
		}
	}
	return result
}

func (o *Object) init() {
	o.id = atomic.AddUint32(&idcounter, 1)
	if o.values == nil {
		o.values = NewAttributeValueMap()
	}
	if o.CanPwn == nil || o.PwnableBy == nil {
		o.CanPwn = make(PwnConnections)
		o.PwnableBy = make(PwnConnections)
	}
}

func (o *Object) StringNoACL() string {
	var result string
	result += "OBJECT " + o.DN() + "\n"
	for attr, values := range o.AttributeValueMap() {
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
	return result
}

func (o *Object) String(ao *Objects) string {
	result := o.StringNoACL()

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
		return nil, errors.New("no security desciptor")
	}
	return o.sdcache, nil
}

func (o *Object) cacheSecurityDescriptor(rawsd []byte) error {
	if len(rawsd) == 0 {
		return errors.New("empty nTSecurityDescriptor attribute!?")
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
		o.lock()
		o.sidcached = true
		if asid, ok := o.get(ObjectSid); ok {
			if asid.Len() == 1 {
				if sid, ok := asid.Slice()[0].Raw().(windowssecurity.SID); ok {
					o.sid = sid
				}
			}
		}
		o.unlock()
	}
	sid := o.sid
	return sid
}

func (o *Object) GUID() uuid.UUID {
	o.lock()
	if !o.guidcached {
		o.guidcached = true
		if aguid, ok := o.get(ObjectGUID); ok {
			if aguid.Len() == 1 {
				if guid, ok := aguid.Slice()[0].Raw().(uuid.UUID); ok {
					o.guid = guid
				}
			}
		}
	}
	guid := o.guid
	o.unlock()
	return guid
}

func (o *Object) Pwns(target *Object, method PwnMethod) {
	o.PwnsEx(target, method, false)
}

func (o *Object) PwnsEx(target *Object, method PwnMethod, force bool) {
	if !force {
		if o == target { // SID check solves (some) dual-AD analysis problems
			// We don't care about self owns
			return
		}

		osid := o.SID()

		// Ignore these, SELF = self own, Creator/Owner always has full rights
		if osid == windowssecurity.SelfSID || osid == windowssecurity.SystemSID {
			return
		}

		tsid := target.SID()
		if osid != windowssecurity.BlankSID && osid == tsid {
			return
		}
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
		// Unlock, as we call thing that lock in the debug message
		o.unlock()
		log.Debug().Msgf("Object already %v has %v as parent, so I'm not assigning %v as parent", o.Label(), o.parent.Label(), parent.Label())
		o.lock()
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
