package engine

import (
	"encoding/xml"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/uuid"
	"github.com/icza/gox/stringsx"
	jsoniter "github.com/json-iterator/go"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var threadbuckets = runtime.NumCPU() * runtime.NumCPU() * 64
var threadsafeobjectmutexes = make([]sync.RWMutex, threadbuckets)

var AttributeNodeId = NewAttribute("nodeID").Flag(Single, Hidden, DropWhenMerging)

var uniqueNodeID atomic.Uint32

var UnknownGUID = uuid.UUID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

var BlankSID = windowssecurity.SID("")

type Node struct {
	sdcache    *SecurityDescriptor
	parent     *Node
	sid        atomic.Value // windowssecurity.SID
	children   NodeSlice
	values     AttributesAndValues
	objecttype NodeType
}

var IgnoreBlanks = "_IGNOREBLANKS_"

func NewNode(flexinit ...any) *Node {
	var result Node
	result.init()
	result.setFlex(flexinit...)

	return &result
}

// Temporary workaround
type NodeID uint32

func (o *Node) ID() NodeID {
	n := o.OneAttr(AttributeNodeId)
	if n == nil {
		return 0
	}
	return NodeID(n.Raw().(int64))
}

func (o *Node) lockbucket() int {
	return int(o.ID()) % threadbuckets
}

func (o *Node) lock() {
	threadsafeobjectmutexes[o.lockbucket()].Lock()
}

func (o *Node) rlock() {
	threadsafeobjectmutexes[o.lockbucket()].RLock()
}

func (o *Node) unlock() {
	threadsafeobjectmutexes[o.lockbucket()].Unlock()
}

func (o *Node) runlock() {
	threadsafeobjectmutexes[o.lockbucket()].RUnlock()
}

func (o *Node) Absorb(source *Node) {
	o.AbsorbEx(source, false)
}

// Absorbs data and edge relationships from another object, sucking the soul out of it
// The sources empty shell should be discarded afterwards (i.e. not appear in an Graph collection)
func (target *Node) AbsorbEx(source *Node, fast bool) {
	if target == source {
		panic("Can't absorb myself")
	}

	newvalues := target.values.Merge(&source.values)
	target.values = *newvalues
}

func mergeValues(v1, v2 AttributeValues) AttributeValues {
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

func (o *Node) NameStringMap() StringMap {
	result := make(StringMap)
	o.values.Iterate(func(attr Attribute, values AttributeValues) bool {
		result[attr.String()] = values.StringSlice()
		return true
	})
	return result
}

func (o *Node) MarshalJSON() ([]byte, error) {
	return jsoniter.ConfigCompatibleWithStandardLibrary.Marshal(o.NameStringMap())
}

func (o *Node) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return o.NameStringMap().MarshalXML(e, start)
}

func (o *Node) IDString() string {
	return strconv.FormatUint(uint64(o.ID()), 10)
}

func (o *Node) DN() string {
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

func (o *Node) Label() string {
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

func (o *Node) PrimaryID() (Attribute, AttributeValue) {
	for _, attr := range primaryidattrs {
		if o.HasAttr(attr) {
			val := o.OneAttr(attr)
			if val != nil {
				return attr, val
			}
		}
	}
	return NonExistingAttribute, NV("N/A")
}

func (o *Node) Type() NodeType {
	if o.objecttype > 0 {
		return o.objecttype
	}

	category := o.Attr(Type)

	if category.Len() == 0 {
		return NodeTypeOther
	}

	objecttype, found := NodeTypeLookup(category.First().String())
	if found {
		o.objecttype = objecttype
	}
	return objecttype
}

func (o *Node) ObjectCategoryGUID(ao *IndexedGraph) uuid.UUID {
	// if o.objectcategoryguid == NullGUID {
	guid := o.OneAttrRaw(ObjectCategoryGUID)
	if guid == nil {
		return UnknownGUID
	}
	return guid.(uuid.UUID)
	// return o.objectcategoryguid
}

func (o *Node) AttrString(attr Attribute) []string {
	return o.Attr(attr).StringSlice()
}

func (o *Node) AttrRendered(attr Attribute) AttributeValues {
	if attr == ObjectCategory && o.HasAttr(Type) {
		return o.Attr(Type)
	}
	return o.Attr(attr)
}

func (o *Node) OneAttrRendered(attr Attribute) string {
	r := o.AttrRendered(attr)
	if r.Len() == 0 {
		return ""
	}
	return r.First().String()
}

// Returns synthetic blank attribute value if it isn't set
func (o *Node) get(attr Attribute) (AttributeValues, bool) {
	if attr == NonExistingAttribute {
		return nil, false
	}
	if attributeinfos[attr].onget != nil {
		return attributeinfos[attr].onget(o, attr)
	}
	return o.values.Get(attr)
}

// Auto locking version
func (o *Node) Get(attr Attribute) (AttributeValues, bool) {
	return o.get(attr)
}

// Returns synthetic blank attribute value if it isn't set
func (o *Node) attr(attr Attribute) AttributeValues {
	if attrs, found := o.get(attr); found {
		if attrs == nil {
			panic(fmt.Sprintf("Looked for attribute %v and found NIL value", attr.String()))
		}
		return attrs
	}
	return nil
}

// Returns synthetic blank attribute value if it isn't set
func (o *Node) Attr(attr Attribute) AttributeValues {
	return o.attr(attr)
}

func (o *Node) OneAttrString(attr Attribute) string {
	a, found := o.get(attr)
	if !found {
		return ""
	}
	if a.Len() != 1 {
		ui.Error().Msgf("Attribute %v lookup for ONE value, but contains %v (%v)", attr.String(), a.Len(), strings.Join(a.StringSlice(), ", "))
	}
	return a.First().String()
}

func (o *Node) OneAttrRaw(attr Attribute) any {
	a := o.Attr(attr)
	if a == nil {
		return nil
	}
	if a.Len() == 1 {
		return a.First().Raw()
	}
	return nil
}

func (o *Node) OneAttr(attr Attribute) AttributeValue {
	a := o.Attr(attr)
	if a == nil {
		return nil
	}
	if a.Len() == 1 {
		return a.First()
	}
	return nil
}

func (o *Node) HasAttr(attr Attribute) bool {
	_, found := o.Get(attr)
	return found
}

func (o *Node) HasAttrValue(attr Attribute, hasvalue AttributeValue) bool {
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

func (o *Node) AttrInt(attr Attribute) (int64, bool) {
	v, ok := o.OneAttrRaw(attr).(int64)
	return v, ok
}

func (o *Node) AttrTime(attr Attribute) (time.Time, bool) {
	v, ok := o.OneAttrRaw(attr).(time.Time)
	return v, ok
}

func (o *Node) AttrBool(attr Attribute) (bool, bool) {
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

func (o *Node) SetFlex(flexinit ...any) {
	o.setFlex(flexinit...)
}

var avsPool = sync.Pool{
	New: func() any {
		avs := make(AttributeValues, 0, 16)
		return &avs
	},
}

func (o *Node) setFlex(flexinit ...any) {
	var ignoreblanks bool

	attribute := NonExistingAttribute

	slice := avsPool.Get().(*AttributeValues)
	data := *slice

	for _, i := range flexinit {
		if i == IgnoreBlanks {
			ignoreblanks = true
			continue
		}
		if i == nil || (reflect.ValueOf(i).Kind() == reflect.Ptr && reflect.ValueOf(i).IsNil()) {
			if ignoreblanks {
				continue
			}
			ui.Fatal().Msgf("Flex initialization with NIL value")
		}
		switch v := i.(type) {
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
				data = append(data, NV(s))
			}
		case []string:
			if ignoreblanks && len(v) == 0 {
				continue
			}
			for _, s := range v {
				if ignoreblanks && s == "" {
					continue
				}
				data = append(data, NV(s))
			}
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
		case Attribute:
			if attribute != NonExistingAttribute && (!ignoreblanks || len(data) > 0) {
				o.set(attribute, data...)
			}
			data = data[:0]
			attribute = v
		default:
			// deref pointers
			if reflect.ValueOf(i).Kind() == reflect.Ptr {
				i = reflect.ValueOf(i).Elem().Interface()
			}

			newvalue := NV(i)
			if newvalue == nil || (ignoreblanks && newvalue.IsZero()) {
				if ignoreblanks {
					continue
				}
				ui.Fatal().Msgf("Flex initialization with NIL value")
			}
			data = append(data, newvalue)
		}
	}
	if attribute != NonExistingAttribute && (!ignoreblanks || len(data) > 0) {
		o.set(attribute, data...)
	}
	data = data[:0]

	*slice = data
	avsPool.Put(slice)
}

func (o *Node) Set(a Attribute, values ...AttributeValue) {
	o.set(a, values...)
}

func (o *Node) Add(a Attribute, values ...AttributeValue) {
	o.add(a, values...)
}

func (o *Node) Clear(a Attribute) {
	o.values.Clear(a)
}

func (o *Node) Tag(v string) {
	if !o.HasTag(v) {
		o.Add(Tag, NV(v))
	}
}

// FIXME performance optimization/redesign needed, but needs to work with Objects indexes
func (o *Node) HasTag(v string) bool {
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

func (o *Node) add(a Attribute, values ...AttributeValue) {
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

func (o *Node) set(a Attribute, values ...AttributeValue) {
	if a.HasFlag(Single) && len(values) > 1 {
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
					ui.Warn().Msgf("Node DataSource and downlevel NETBIOS name conflict: %v / %v", value.String(), o.OneAttrString(DataSource))
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

func (o *Node) Meta() map[string]string {
	result := make(map[string]string)
	o.AttrIterator(func(attr Attribute, value AttributeValues) bool {
		if attr.String()[0] == '_' {
			result[attr.String()] = value.First().String()
		}
		return true
	})
	return result
}

func (o *Node) init() {
	o.values.init()
	o.Set(AttributeNodeId, NV(uniqueNodeID.Add(1)))
}

func (o *Node) String() string {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("Node %v\n", o.ID()))

	o.AttrIterator(func(attr Attribute, values AttributeValues) bool {
		if attr == NTSecurityDescriptor {
			return true // continue
		}
		result.WriteString(" ")
		result.WriteString(attributeinfos[attr].name)
		result.WriteString(":\n")
		values.Iterate(func(value AttributeValue) bool {
			cleanval := stringsx.Clean(value.String())
			if cleanval != value.String() {
				result.WriteString(fmt.Sprintf("    %v (%v original, %v cleaned)\n", value, len(value.String()), len(cleanval)))
			} else {
				result.WriteString("    ")
				result.WriteString(value.String())
				result.WriteString("\n")
			}
			return true
		})

		return true // one more
	})
	return result.String()
}

func (o *Node) StringACL(ao *IndexedGraph) string {
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
func (o *Node) ValueMap() map[string][]string {
	result := make(map[string][]string)
	o.AttrIterator(func(attr Attribute, values AttributeValues) bool {
		result[attr.String()] = values.StringSlice()
		return true
	})
	return result
}

var ErrNoSecurityDescriptor = errors.New("no security desciptor")

// Return parsed security descriptor
func (o *Node) SecurityDescriptor() (*SecurityDescriptor, error) {
	if o.sdcache == nil {
		return nil, ErrNoSecurityDescriptor
	}
	return o.sdcache, nil
}

var ErrEmptySecurityDescriptorAttribute = errors.New("empty nTSecurityDescriptor attribute!?")

// Return the object's SID
func (o *Node) SID() windowssecurity.SID {
	var sid windowssecurity.SID
	cachedSid := o.sid.Load()
	if cachedSid == nil {
		if asid, ok := o.get(ObjectSid); ok {
			if asid.Len() == 1 {
				if sid, ok = asid.First().Raw().(windowssecurity.SID); ok {
					o.sid.Store(sid)
					cachedSid = sid
				}
			}
		}
		if cachedSid == nil { // Still not found, so cache blank
			o.sid.Store(BlankSID)
			cachedSid = BlankSID
		}
	}
	return cachedSid.(windowssecurity.SID)
}

// Look up edge
// func (o *Object) Edge(direction EdgeDirection, target *Object) EdgeBitmap {
// 	bm, _ := o.edges[direction].Get(target)
// 	return bm
// }

func (o *Node) AttrIterator(f func(attr Attribute, avs AttributeValues) bool) {
	o.values.Iterate(f)
}

func (o *Node) ChildOf(parent *Node) {
	if o.parent != nil {
		// Unlock, as we call thing that lock in the debug message
		ui.Trace().Msgf("Node %v already has %v as parent, so I'm not assigning %v as parent", o.Label(), o.parent.Label(), parent.Label())
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

func (o *Node) childOf(parent *Node) {
	if o.parent != nil {
		ui.Debug().Msgf("Node %v already has %v as parent, so I'm not assigning %v as parent", o.Label(), o.parent.Label(), parent.Label())
		return
	}
	o.parent = parent
	parent.children.Add(o)
}

func (o *Node) Adopt(child *Node) {
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

func (o *Node) adopt(child *Node) {
	if child.parent == nil {
		panic("can't adopt same child twice")
	}
	o.children.Add(child)

	if child.parent != nil {
		child.parent.removeChild(child)
	}
	child.parent = o
}

func (o *Node) hasChild(child *Node) bool {
	var found bool
	o.children.Iterate(func(existingchild *Node) bool {
		if existingchild == child {
			found = true
			return false
		}
		return true
	})
	return found
}

func (o *Node) removeChild(child *Node) {
	o.children.Remove(child)
}

func (o *Node) Parent() *Node {
	o.rlock()
	parent := o.parent
	o.runlock()
	return parent
}

func (o *Node) Children() NodeSlice {
	o.rlock()
	defer o.runlock()
	return o.children
}
