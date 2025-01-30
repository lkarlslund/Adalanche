package engine

import (
	"encoding/xml"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gsync "github.com/SaveTheRbtz/generic-sync-map-go"
	"github.com/gofrs/uuid"
	"github.com/icza/gox/stringsx"
	jsoniter "github.com/json-iterator/go"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var threadbuckets = runtime.NumCPU() * runtime.NumCPU() * 64
var threadsafeobjectmutexes = make([]sync.RWMutex, threadbuckets)

var UnknownGUID = uuid.UUID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type Object struct {
	edges   [2]EdgeConnectionsPlus
	values  AttributesAndValues
	sdcache *SecurityDescriptor
	parent  *Object
	sid     windowssecurity.SID

	children ObjectSlice

	status    atomic.Uint32 // 0 = uninitialized, 1 = valid, 2 = being absorbed, 3 = gone
	id        ObjectID
	sidcached atomic.Bool

	objecttype ObjectType
}

var IgnoreBlanks = "_IGNOREBLANKS_"

func NewObject(flexinit ...any) *Object {
	var result Object
	result.init()
	result.setFlex(flexinit...)

	return &result
}

func (o *Object) ID() ObjectID {
	o.panicIfNotValid()
	return o.id
}

func (o *Object) IsValid() bool {
	return o.status.Load() == 1
}

func (o *Object) panicIfNotValid() {
	if o.status.Load() != 1 {
		panic(fmt.Sprintf("object is not valid: %v", o.status.Load()))
	}
}

func (o *Object) lockbucket() int {
	return int(o.id) % threadbuckets
}

func (o *Object) lock() {
	threadsafeobjectmutexes[o.lockbucket()].Lock()
}

func (o *Object) trylock() bool {
	return threadsafeobjectmutexes[o.lockbucket()].TryLock()
}

func (o *Object) rlock() {
	threadsafeobjectmutexes[o.lockbucket()].RLock()
}

func (o *Object) unlock() {
	threadsafeobjectmutexes[o.lockbucket()].Unlock()
}

func (o *Object) runlock() {
	threadsafeobjectmutexes[o.lockbucket()].RUnlock()
}

// var lockwithMu sync.Mutex

func (o *Object) lockwith(o2 *Object) {
	ol := o.lockbucket()
	ol2 := o2.lockbucket()

	if ol == ol2 {
		o.lock()
		return
	}

	if ol > ol2 {
		o, o2 = o2, o
	}

	// lockwithMu.Lock() // Prevent deadlocks
	o.lock()
	o2.lock()
	// lockwithMu.Unlock()
}

func (o *Object) unlockwith(o2 *Object) {
	ol := o.lockbucket()
	ol2 := o2.lockbucket()

	if ol == ol2 {
		o.unlock()
		return
	}

	if ol > ol2 {
		o, o2 = o2, o
	}

	o2.unlock()
	o.unlock()
}

var ongoingAbsorbs gsync.MapOf[*Object, *Object]

func (o *Object) Absorb(source *Object) {
	o.AbsorbEx(source, false)
}

var absorbCriticalSection sync.Mutex

// Absorbs data and Pwn relationships from another object, sucking the soul out of it
// The sources empty shell should be discarded afterwards (i.e. not appear in an Objects collection)
func (target *Object) AbsorbEx(source *Object, fast bool) {

	if target == source {
		panic("Can't absorb myself")
	}

	// Keep normies out
	// target.lockwith(source)

	// ongoingAbsorbs.Store(source, target)
	absorbCriticalSection.Lock()

	if !source.status.CompareAndSwap(1, 2) {
		// We're being absorbed, nom nom
		panic("Can only absorb valid objects")
	}

	// Fast mode does not merge values, it just relinks the source to the target
	if fast {
		// Just merge this one
		val := MergeValues(source.attr(DataSource), target.attr(DataSource))
		if val != nil {
			target.set(DataSource, val...)
		}
	} else {
		newvalues := target.values.Merge(&source.values)
		target.values = *newvalues
	}

	// fmt.Println("----------------------------------------")

	edgesdone := false
	for !edgesdone {
		edgesdone = true
		source.edges[Out].Range(func(outgoingTarget *Object, edges EdgeBitmap) bool {
			edgesdone = false
			if source == outgoingTarget {
				panic("Pointing at myself")
			}

			// Load edges from target, and merge with source edges
			target.edges[Out].setEdges(outgoingTarget, edges)
			source.edges[Out].del(outgoingTarget)

			/*

				// The target has incoming edges, so redirect those
				moveto := outgoingTarget

				for moveto.status.Load() == 2 {
					var success bool
					moveto, success = ongoingAbsorbs.Load(moveto)
					if !success {
						panic("Could not map to next ongoing absorb")
					}
				}

				if moveto == target {
					panic("Moveto pointing at target")
				}
				if moveto == source {
					panic("Moveto pointing at source")
				}

				moveto.edges[In].setEdges(target, edges)
			*/

			outgoingTarget.edges[In].setEdges(target, edges)
			outgoingTarget.edges[In].del(source)

			return true
		})
	}

	// Someone is pointing at us, so we need to help them to point to our new target

	edgesdone = false
	for !edgesdone {
		edgesdone = true
		source.edges[In].Range(func(incomingTarget *Object, edges EdgeBitmap) bool {
			edgesdone = false
			if source == incomingTarget {
				panic("Pointing at myself")
			}

			target.edges[In].setEdges(incomingTarget, edges)
			source.edges[In].del(incomingTarget)

			/*
				// The target has incoming edges, so redirect those
				moveto := incomingTarget
				for moveto.status.Load() == 2 {
					var success bool
					moveto, success = ongoingAbsorbs.Load(moveto)
					if !success {
						panic("Could not map to next ongoing absorb")
					}
				}

				if moveto == target {
					panic("Moveto pointing at target")
				}
				if moveto == source {
					panic("Moveto pointing at source")
				}

				moveto.edges[Out].setEdges(target, edges)
			*/

			incomingTarget.edges[Out].setEdges(target, edges)
			incomingTarget.edges[Out].del(source)

			return true
		})
	}

	// If the source has a parent, but the target doesn't we assimilate that role (muhahaha)
	if source.parent != nil {
		moveto := source.parent
		for moveto.status.Load() == 2 {
			var success bool
			moveto, success = ongoingAbsorbs.Load(moveto)
			if !success {
				panic("Not a great day, is it")
			}
		}

		if target.parent == nil {
			target.parent = moveto
			moveto.children.Add(target)
		}
		if moveto == source.parent {
			moveto.removeChild(source)
		}
		source.parent = nil
	}

	source.children.Iterate(func(child *Object) bool {
		if child.parent != source {
			panic("Child/parent mismatch")
		}
		target.children.Add(child)

		child.parent = target
		return true
	})
	source.children = ObjectSlice{}

	// Move the securitydescriptor, as we dont have the attribute saved to regenerate it (we throw it away at import after populating the cache)
	if source.sdcache != nil && target.sdcache != nil {
		// Both has a cache
		if !source.sdcache.Equals(target.sdcache) {
			// Different caches, so we need to merge them which is impossible
			ui.Error().Msgf("Can not merge security descriptors between %v and %v", source.Label(), target.Label())
		}
	} else if target.sdcache == nil && source.sdcache != nil {
		target.sdcache = source.sdcache
	}

	target.objecttype = 0 // Recalculate this

	// Nom nommed
	if !source.status.CompareAndSwap(2, 3) {
		panic("Unpossible absorption mutation occurred")
	}
	// ongoingAbsorbs.Delete(source)

	absorbCriticalSection.Unlock()

	/*
		// Disable this when everything is under control
		if source.edges[Out].Len() > 0 || source.edges[In].Len() > 0 {
			source.edges[In].Range(func(o *Object, edges EdgeBitmap) bool {
				ui.Debug().Msgf("In: %v", o.Label())
				return true
			})
			source.edges[Out].Range(func(o *Object, edges EdgeBitmap) bool {
				ui.Debug().Msgf("Out: %v", o.Label())
				return true
			})
			panic("WTF")
		}
	*/

	// target.unlockwith(source)
}

func MergeValues(v1, v2 AttributeValues) AttributeValues {
	if v1.Len() == 0 {
		return v2
	}
	if v2.Len() == 0 {
		return v1
	}
	if v1.Len() == 1 && v2.Len() == 1 {
		if CompareAttributeValues(v1[0], v2[0]) {
			return v1 // They're the same, so pick any
		}
		// They're not the same, join them
		return AttributeValues{v1[0], v2[0]}
	}

	slices.SortFunc(v1, CompareAttributeValuesInt)
	slices.SortFunc(v2, CompareAttributeValuesInt)
	resultingvalues := make(AttributeValues, 0, len(v1)+len(v2))

	// Perform a merge sort of v1 and v2 into resultingvalues
	i := 0
	j := 0
	for i < len(v1) && j < len(v2) {
		comparison := CompareAttributeValuesInt(v1[i], v2[j])
		if comparison < 0 {
			resultingvalues = append(resultingvalues, v1[i])
			i++
		} else if comparison == 0 {
			resultingvalues = append(resultingvalues, v1[i])
			i++
			j++ // dedup
		} else {
			resultingvalues = append(resultingvalues, v2[j])
			j++
		}
	}
	if i < len(v1) {
		resultingvalues = append(resultingvalues, v1[i:]...)
	}
	if j < len(v2) {
		resultingvalues = append(resultingvalues, v2[j:]...)
	}

	return resultingvalues
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
	result := make(StringMap)
	o.values.Iterate(func(attr Attribute, values AttributeValues) bool {
		result[attr.String()] = values.StringSlice()
		return true
	})
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

var primaryidattrs = []Attribute{
	DistinguishedName,
	ObjectGUID,
	ObjectSid, // Danger, Will Robinson
}

func (o *Object) PrimaryID() (Attribute, AttributeValue) {
	for _, attr := range primaryidattrs {
		if o.HasAttr(attr) {
			val := o.OneAttr(attr)
			if val != nil {
				return attr, val
			}
		}
	}
	return NonExistingAttribute, NewAttributeValueString("N/A")
}

func (o *Object) Type() ObjectType {
	if o.objecttype > 0 {
		return o.objecttype
	}

	category := o.Attr(Type)

	if category.Len() == 0 {
		return ObjectTypeOther
	}

	objecttype, found := ObjectTypeLookup(category.First().String())
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

func (o *Object) AttrRendered(attr Attribute) AttributeValues {
	if attr == ObjectCategory && o.HasAttr(Type) {
		return o.Attr(Type)
	}
	return o.Attr(attr)
}

func (o *Object) OneAttrRendered(attr Attribute) string {
	r := o.AttrRendered(attr)
	if r.Len() == 0 {
		return ""
	}
	return r.First().String()
}

// Returns synthetic blank attribute value if it isn't set
func (o *Object) get(attr Attribute) (AttributeValues, bool) {
	if attr == NonExistingAttribute {
		return nil, false
	}
	if attributeinfos[attr].onget != nil {
		return attributeinfos[attr].onget(o, attr)
	}
	return o.values.Get(attr)
}

// Auto locking version
func (o *Object) Get(attr Attribute) (AttributeValues, bool) {
	o.panicIfNotValid()
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
	return nil
}

// Returns synthetic blank attribute value if it isn't set
func (o *Object) Attr(attr Attribute) AttributeValues {
	o.panicIfNotValid()
	return o.attr(attr)
}

func (o *Object) OneAttrString(attr Attribute) string {
	a, found := o.get(attr)
	if !found {
		return ""
	}
	if a.Len() != 1 {
		ui.Error().Msgf("Attribute %v lookup for ONE value, but contains %v (%v)", attr.String(), a.Len(), strings.Join(a.StringSlice(), ", "))
	}
	return a.First().String()
}

func (o *Object) OneAttrRaw(attr Attribute) any {
	a := o.Attr(attr)
	if a == nil {
		return nil
	}
	if a.Len() == 1 {
		return a.First().Raw()
	}
	return nil
}

func (o *Object) OneAttr(attr Attribute) AttributeValue {
	a := o.Attr(attr)
	if a == nil {
		return nil
	}
	if a.Len() == 1 {
		return a.First()
	}
	return nil
}

func (o *Object) HasAttr(attr Attribute) bool {
	_, found := o.Get(attr)
	return found
}

func (o *Object) HasAttrValue(attr Attribute, hasvalue AttributeValue) bool {
	var result bool
	o.Attr(attr).Iterate(func(value AttributeValue) bool {
		if CompareAttributeValues(value, hasvalue) {
			result = true
			return false
		}
		return true
	})
	return result
}

func (o *Object) AttrInt(attr Attribute) (int64, bool) {
	v, ok := o.OneAttrRaw(attr).(int64)
	return v, ok
}

func (o *Object) AttrTime(attr Attribute) (time.Time, bool) {
	v, ok := o.OneAttrRaw(attr).(time.Time)
	return v, ok
}

func (o *Object) AttrBool(attr Attribute) (bool, bool) {
	v, ok := o.OneAttrRaw(attr).(bool)
	return v, ok
}

/*
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
	// ui.Debug().Msgf("Converted %v to %v", v, t)
	return t, true
}
*/

func (o *Object) SetFlex(flexinit ...any) {
	o.setFlex(flexinit...)
}

var avsPool = sync.Pool{
	New: func() any {
		avs := make(AttributeValues, 0, 16)
		return &avs
	},
}

func (o *Object) setFlex(flexinit ...any) {
	var ignoreblanks bool

	attribute := NonExistingAttribute

	slice := avsPool.Get().(*AttributeValues)
	data := *slice

	for _, i := range flexinit {
		if i == IgnoreBlanks {
			ignoreblanks = true
			continue
		}
		if i == nil {
			if ignoreblanks {
				continue
			}
			ui.Fatal().Msgf("Flex initialization with NIL value")
		}
		switch v := i.(type) {
		case windowssecurity.SID:
			if ignoreblanks && v.IsNull() {
				continue
			}
			data = append(data, NewAttributeValueSID(v))
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
				data = append(data, NewAttributeValueString(s))
			}
		case []string:
			if ignoreblanks && len(v) == 0 {
				continue
			}
			for _, s := range v {
				if ignoreblanks && s == "" {
					continue
				}
				data = append(data, NewAttributeValueString(s))
			}
		case *string:
			if v == nil {
				continue
			}
			if ignoreblanks && len(*v) == 0 {
				continue
			}
			data = append(data, NewAttributeValueString(*v))
		case string:
			if ignoreblanks && len(v) == 0 {
				continue
			}
			data = append(data, NewAttributeValueString(v))
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
		case uuid.UUID:
			if ignoreblanks && v.IsNil() {
				continue
			}
			data = append(data, NewAttributeValueGUID(v))
		case *uuid.UUID:
			if ignoreblanks && v.IsNil() {
				continue
			}
			data = append(data, NewAttributeValueGUID(*v))
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
		case uint64:
			if ignoreblanks && v == 0 {
				continue
			}
			data = append(data, AttributeValueInt(v))
		case AttributeValue:
			if ignoreblanks && v.IsZero() {
				continue
			}
			data = append(data, v)
		case []AttributeValue:
			for _, value := range v {
				if ignoreblanks && value.IsZero() {
					continue
				}
				data = append(data, value)
			}
		case AttributeValues:
			for _, value := range v {
				if ignoreblanks && value.IsZero() {
					continue
				}
				data = append(data, value)
			}
		case nil:
			// Ignore it, this doesn't work?
		case Attribute:
			if attribute != NonExistingAttribute && (!ignoreblanks || len(data) > 0) {
				o.set(attribute, data...)
			}
			data = data[:0]
			attribute = v
		default:
			panic("SetFlex called with invalid type in object declaration")
		}
	}
	if attribute != NonExistingAttribute && (!ignoreblanks || len(data) > 0) {
		o.set(attribute, data...)
	}
	data = data[:0]

	*slice = data
	avsPool.Put(slice)
}

func (o *Object) Set(a Attribute, values ...AttributeValue) {
	o.set(a, values...)
}

func (o *Object) Add(a Attribute, values ...AttributeValue) {
	o.add(a, values...)
}

func (o *Object) Clear(a Attribute) {
	o.values.Clear(a)
}

func (o *Object) Tag(v string) {
	if !o.HasTag(v) {
		o.Add(Tag, NewAttributeValueString(v))
	}
}

// FIXME performance optimization/redesign needed, but needs to work with Objects indexes
func (o *Object) HasTag(v string) bool {
	tags, found := o.Get(Tag)
	if !found {
		return false
	}
	var exists bool
	tags.Iterate(func(val AttributeValue) bool {
		if val.String() == v {
			exists = true
			return false
		}
		return true
	})
	return exists
}

func (o *Object) add(a Attribute, values ...AttributeValue) {
	oldvalues, found := o.values.Get(a)
	if !found {
		o.set(a, values...)
	} else {
		data := make([]AttributeValue, len(oldvalues)+len(values))
		copy(data, oldvalues)
		copy(data[len(oldvalues):], values)
		o.set(a, data...)
	}
}

func (o *Object) set(a Attribute, values ...AttributeValue) {
	if a.IsSingle() && len(values) > 1 {
		ui.Warn().Msgf("Setting multiple values on non-multival attribute %v: %v", a.String(), strings.Join(AttributeValues(values).StringSlice(), ", "))
	}

	if a == NTSecurityDescriptor {
		o.sdcache = values[0].Raw().(*SecurityDescriptor)
	}

	if a == DownLevelLogonName {
		// There's been so many problems with DLLN that we're going to just check for these
		if len(values) != 1 {
			ui.Warn().Msgf("Found DownLevelLogonName with multiple values: %v", strings.Join(AttributeValues(values).StringSlice(), ", "))
		}
		AttributeValues(values).Iterate(func(value AttributeValue) bool {
			dlln := value.String()
			if dlln == "," {
				ui.Fatal().Msgf("Setting DownLevelLogonName to ',' is not allowed")
			}
			if dlln == "" {
				ui.Fatal().Msgf("Setting DownLevelLogonName to blank is not allowed")
			}
			if strings.HasPrefix(dlln, "S-") {
				ui.Warn().Msgf("DownLevelLogonName contains SID: %v", AttributeValues(values).StringSlice())
			}
			if strings.HasSuffix(dlln, "\\") {
				ui.Fatal().Msgf("DownLevelLogonName %v ends with \\", dlln)
			}

			dotpos := strings.Index(dlln, ".")
			if dotpos >= 0 {
				backslashpos := strings.Index(dlln, "\\")
				if dotpos < backslashpos {
					ui.Warn().Msgf("DownLevelLogonName contains dot in domain: %v", dlln)
				}
			}

			if o.HasAttr(DataSource) {
				netbios, _, didsplit := strings.Cut(dlln, "\\")
				datasource := o.OneAttrString(DataSource)
				if didsplit &&
					!strings.EqualFold(datasource, netbios) &&
					!strings.HasPrefix(netbios, "NT-") &&
					!strings.HasPrefix(netbios, "NT ") &&
					!strings.HasSuffix(netbios, " NT") &&
					netbios != "BUILTIN" &&
					netbios != "IIS APPPOOL" {
					ui.Warn().Msgf("Object DataSource and downlevel NETBIOS name conflict: %v / %v", value.String(), o.OneAttrString(DataSource))
				}
			}

			return true
		})
	}

	if a == ObjectCategory || a == Type {
		// Clear objecttype cache attribute
		o.objecttype = 0
	}

	// Check it's not nil
	for _, value := range values {
		if value == nil {
			panic("tried to set nil value")
		}
	}

	o.values.Set(a, values)
}

func (o *Object) Meta() map[string]string {
	result := make(map[string]string)
	o.AttrIterator(func(attr Attribute, value AttributeValues) bool {
		if attr.String()[0] == '_' {
			result[attr.String()] = value.First().String()
		}
		return true
	})
	return result
}

func (o *Object) init() {
	o.id = ObjectID(atomic.AddUint32(&idcounter, 1))
	o.values.init()
	o.status.Store(1)
}

func (o *Object) String() string {
	var result string
	result += "OBJECT " + o.DN() + "\n"
	o.AttrIterator(func(attr Attribute, values AttributeValues) bool {
		if attr == NTSecurityDescriptor {
			return true // continue
		}
		result += "  " + attributeinfos[attr].name + ":\n"
		values.Iterate(func(value AttributeValue) bool {
			cleanval := stringsx.Clean(value.String())
			if cleanval != value.String() {
				result += fmt.Sprintf("    %v (%v original, %v cleaned)\n", value, len(value.String()), len(cleanval))
			} else {
				result += "    " + value.String() + "\n"
			}
			return true
		})

		return true // one more
	})
	return result
}

func (o *Object) StringACL(ao *Objects) string {
	result := o.String()

	sd, err := o.SecurityDescriptor()
	if err == nil {
		result += "----- SECURITY DESCRIPTOR DUMP -----\n"
		result += sd.String(ao)
	}
	result += "---------------\n"
	return result
}

// Dump the object to simple map type for debugging
func (o *Object) ValueMap() map[string][]string {
	result := make(map[string][]string)
	o.AttrIterator(func(attr Attribute, values AttributeValues) bool {
		result[attr.String()] = values.StringSlice()
		return true
	})
	return result
}

var ErrNoSecurityDescriptor = errors.New("no security desciptor")

// Return parsed security descriptor
func (o *Object) SecurityDescriptor() (*SecurityDescriptor, error) {
	if o.sdcache == nil {
		return nil, ErrNoSecurityDescriptor
	}
	return o.sdcache, nil
}

var ErrEmptySecurityDescriptorAttribute = errors.New("empty nTSecurityDescriptor attribute!?")

// Return the object's SID
func (o *Object) SID() windowssecurity.SID {
	if !o.sidcached.Load() {
		if asid, ok := o.get(ObjectSid); ok {
			if asid.Len() == 1 {
				if sid, ok := asid.First().Raw().(windowssecurity.SID); ok {
					o.sid = sid
				}
			}
		}
		o.sidcached.Store(true)
	}
	sid := o.sid
	return sid
}

// Look up edge
// func (o *Object) Edge(direction EdgeDirection, target *Object) EdgeBitmap {
// 	bm, _ := o.edges[direction].Get(target)
// 	return bm
// }

// Register that this object can pwn another object using the given method
func (o *Object) EdgeTo(target *Object, edge Edge) {
	o.EdgeToEx(target, edge, false)
}

// Register that this object can pwn another object using the given method
func (o *Object) GetEdge(target *Object) (EdgeBitmap, bool) {
	edge, ok := o.Edges(Out).Load(Connection{target: target})
	return edge.edges, ok
}

// Enhanched Pwns function that allows us to force the pwn (normally self-pwns are filtered out)
func (o *Object) EdgeToEx(target *Object, edge Edge, force bool) {
	if o == target {
		// Self-loop not supported
		return
	}

	if !force {
		osid := o.SID()

		// Ignore these, SELF = self own, Creator/Owner always has full rights
		if osid == windowssecurity.SelfSID {
			return
		}

		tsid := target.SID()
		if !osid.IsBlank() && osid == tsid {
			return
		}
	}

	o.Edges(Out).setEdge(target, edge)
	target.Edges(In).setEdge(o, edge)
}

// Register that this object can pwn another object using the given method
func (o *Object) EdgeClear(target *Object, edge Edge) {
	if o == target {
		return
	}
	o.Edges(Out).clearEdge(target, edge)
	target.Edges(In).clearEdge(o, edge)
}

type ObjectEdge struct {
	o *Object
	e EdgeBitmap
}

func (o *Object) Edges(direction EdgeDirection) *EdgeConnectionsPlus {
	o.panicIfNotValid()
	return &o.edges[direction]
}

func (o *Object) EdgeIteratorRecursive(direction EdgeDirection, edgeMatch EdgeBitmap, excludemyself bool, goDeeperFunc func(source, target *Object, edge EdgeBitmap, depth int) bool) {
	o.panicIfNotValid()
	seenobjects := make(map[*Object]struct{})
	if excludemyself {
		seenobjects[o] = struct{}{}
	}
	o.edgeIteratorRecursive(direction, edgeMatch, goDeeperFunc, seenobjects, 1)
}

func (o *Object) edgeIteratorRecursive(direction EdgeDirection, edgeMatch EdgeBitmap, goDeeperFunc func(source, target *Object, edge EdgeBitmap, depth int) bool, appliedTo map[*Object]struct{}, depth int) {
	o.Edges(direction).Range(func(target *Object, edge EdgeBitmap) bool {
		if _, found := appliedTo[target]; !found {
			edgeMatches := edge.Intersect(edgeMatch)
			if !edgeMatches.IsBlank() {
				appliedTo[target] = struct{}{}
				if goDeeperFunc(o, target, edgeMatches, depth) {
					target.edgeIteratorRecursive(direction, edgeMatch, goDeeperFunc, appliedTo, depth+1)
				}
			}
		}
		return true
	})
}

func (o *Object) AttrIterator(f func(attr Attribute, avs AttributeValues) bool) {
	o.values.Iterate(f)
}

func (o *Object) ChildOf(parent *Object) {
	if o.parent != nil {
		// Unlock, as we call thing that lock in the debug message
		ui.Debug().Msgf("Object %v already has %v as parent, so I'm not assigning %v as parent", o.Label(), o.parent.Label(), parent.Label())
		return
		// panic("objects can only have one parent")
	}
	o.lock()
	o.parent = parent
	o.unlock()
	parent.lock()
	parent.children.Add(o)
	parent.unlock()
}

func (o *Object) childOf(parent *Object) {
	if o.parent != nil {
		ui.Debug().Msgf("Object %v already has %v as parent, so I'm not assigning %v as parent", o.Label(), o.parent.Label(), parent.Label())
		return
	}
	o.parent = parent
	parent.children.Add(o)
}

func (o *Object) Adopt(child *Object) {
	o.lock()
	if o.hasChild(child) {
		panic("can't adopt same child twice")
	}
	o.children.Add(child)
	o.unlock()

	child.lock()
	if child.parent != nil {
		parent := child.parent
		parent.lock()
		parent.removeChild(child)
		parent.unlock()
	}
	child.parent = o
	child.unlock()
}

func (o *Object) adopt(child *Object) {
	if child.parent == nil {
		panic("can't adopt same child twice")
	}
	o.children.Add(child)

	if child.parent != nil {
		child.parent.removeChild(child)
	}
	child.parent = o
}

func (o *Object) hasChild(child *Object) bool {
	var found bool
	o.children.Iterate(func(existingchild *Object) bool {
		if existingchild == child {
			found = true
			return false
		}
		return true
	})
	return found
}

func (o *Object) removeChild(child *Object) {
	o.children.Remove(child)
}

func (o *Object) Parent() *Object {
	o.rlock()
	parent := o.parent
	o.runlock()
	return parent
}

func (o *Object) Children() ObjectSlice {
	o.rlock()
	defer o.runlock()
	return o.children
}
