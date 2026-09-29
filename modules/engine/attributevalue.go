package engine

import (
	"bytes"
	"cmp"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func CompareAttributeValues(a, b AttributeValue) bool {
	if a == b {
		return true
	}
	if a.IsNil() || b.IsNil() {
		return false
	}
	return a.Compare(b) == 0
}

func CompareAttributeValuesInt(a, b AttributeValue) int {
	if a == b {
		return 0
	}
	if a.IsNil() {
		return -1
	} else if b.IsNil() {
		return 1
	}
	return a.Compare(b)
}

// AttributeValues can contain one or more values
type AttributeValues []AttributeValue

func (avs AttributeValues) Sort() {
	if avs == nil {
		return
	}
	slices.SortFunc(avs, CompareAttributeValuesInt)
}

func (avs AttributeValues) First() AttributeValue {
	if len(avs) == 0 {
		return AttributeValue{}
	}
	return avs[0]
}

func (avs AttributeValues) Iterate(it func(val AttributeValue) bool) {
	for _, cval := range avs {
		if !it(cval) {
			break
		}
	}
}

func (avs AttributeValues) StringSlice() []string {
	result := make([]string, len(avs))
	for i := range avs {
		result[i] = avs[i].String()
	}
	return result
}

func (avs AttributeValues) Len() int {
	return len(avs)
}

type valueKind uint8

const (
	kindNil valueKind = iota
	kindString
	kindBool
	kindInt
	kindFloat
	kindTime      // bits: 100ns ticks since 0001-01-01 UTC
	kindTimeTable // bits: index into timeTable, for times the tick form cannot hold exactly
	kindSID       // bits: index into stringTable
	kindGUID      // bits: index into guidTable
	kindNode      // bits: index into nodeTable
	kindSD        // bits: index into sdTable
)

// AttributeValue is a compact, pointer-free value. Scalars are stored inline;
// strings, SIDs, GUIDs, nodes and security descriptors are handles into
// process-wide append-only tables, so values never need to be traced by the
// garbage collector and equal strings or GUIDs compare as equal handles.
// The zero AttributeValue is "no value" (see IsNil).
type AttributeValue struct {
	kind valueKind
	bits uint64
}

// Typed constructors avoid the interface conversion NV needs, which allocates
// for strings and most other kinds when the caller's value escapes.
func NVString(s string) AttributeValue {
	return AttributeValue{kindString, uint64(stringTable.intern(s))}
}

func NVSID(s windowssecurity.SID) AttributeValue {
	return AttributeValue{kindSID, uint64(stringTable.intern(string(s)))}
}

func NVGUID(g uuid.UUID) AttributeValue {
	return AttributeValue{kindGUID, uint64(guidTable.intern(g))}
}

func NVInt(i int64) AttributeValue {
	return AttributeValue{kindInt, uint64(i)}
}

func NVBool(b bool) AttributeValue {
	return boolValue(b)
}

func NVTime(t time.Time) AttributeValue {
	return timeValue(t)
}

func NV(v any) AttributeValue {
	switch val := v.(type) {
	case nil:
		return AttributeValue{}
	case AttributeValue:
		return val
	case string:
		return NVString(val)
	case *bool:
		if val == nil {
			return AttributeValue{}
		}
		return boolValue(*val)
	case bool:
		return boolValue(val)
	case int:
		return AttributeValue{kindInt, uint64(int64(val))}
	case int32:
		return AttributeValue{kindInt, uint64(int64(val))}
	case uint32:
		return AttributeValue{kindInt, uint64(val)}
	case int64:
		return AttributeValue{kindInt, uint64(val)}
	case uint64:
		return AttributeValue{kindInt, val}
	case time.Time:
		return timeValue(val)
	case windowssecurity.SID:
		return NVSID(val)
	case uuid.UUID:
		return NVGUID(val)
	case float32:
		return AttributeValue{kindFloat, math.Float64bits(float64(val))}
	case float64:
		return AttributeValue{kindFloat, math.Float64bits(val)}
	case *Node:
		if val == nil {
			return AttributeValue{}
		}
		return AttributeValue{kindNode, uint64(nodeTable.intern(val))}
	case *SecurityDescriptor:
		if val == nil {
			return AttributeValue{}
		}
		return AttributeValue{kindSD, uint64(sdTable.intern(val))}
	default:
		panic("unsupported attribute value type")
	}
}

func boolValue(b bool) AttributeValue {
	if b {
		return AttributeValue{kindBool, 1}
	}
	return AttributeValue{kindBool, 0}
}

const (
	ticksPerSecond   = 10_000_000
	unixToYearOneSec = 62135596800 // seconds from 0001-01-01 to 1970-01-01
)

// UTC times on a 100ns boundary between years 1 and 9999 are stored inline.
// Anything else keeps its exact time.Time, including location, in a table.
func timeValue(t time.Time) AttributeValue {
	if t.Location() == time.UTC && t.Nanosecond()%100 == 0 {
		sec := t.Unix() + unixToYearOneSec
		if sec >= 0 && sec < 315537897600 { // before year 10000
			return AttributeValue{kindTime, uint64(sec)*ticksPerSecond + uint64(t.Nanosecond()/100)}
		}
	}
	return AttributeValue{kindTimeTable, uint64(timeTable.intern(t))}
}

// IsNil reports whether this is the empty "no value" value.
func (v AttributeValue) IsNil() bool {
	return v.kind == kindNil
}

func (v AttributeValue) AsString() (string, bool) {
	if v.kind != kindString {
		return "", false
	}
	return stringTable.get(uint32(v.bits)), true
}

func (v AttributeValue) AsBool() (bool, bool) {
	return v.bits != 0, v.kind == kindBool
}

func (v AttributeValue) AsInt() (int64, bool) {
	return int64(v.bits), v.kind == kindInt
}

func (v AttributeValue) AsFloat() (float64, bool) {
	if v.kind != kindFloat {
		return 0, false
	}
	return math.Float64frombits(v.bits), true
}

func (v AttributeValue) AsTime() (time.Time, bool) {
	switch v.kind {
	case kindTime:
		sec := int64(v.bits/ticksPerSecond) - unixToYearOneSec
		return time.Unix(sec, int64(v.bits%ticksPerSecond)*100).UTC(), true
	case kindTimeTable:
		return timeTable.get(uint32(v.bits)), true
	}
	return time.Time{}, false
}

func (v AttributeValue) AsSID() (windowssecurity.SID, bool) {
	if v.kind != kindSID {
		return "", false
	}
	return windowssecurity.SID(stringTable.get(uint32(v.bits))), true
}

func (v AttributeValue) AsGUID() (uuid.UUID, bool) {
	if v.kind != kindGUID {
		return uuid.Nil, false
	}
	return guidTable.get(uint32(v.bits)), true
}

func (v AttributeValue) AsNode() (*Node, bool) {
	if v.kind != kindNode {
		return nil, false
	}
	return nodeTable.get(uint32(v.bits)), true
}

func (v AttributeValue) AsSecurityDescriptor() (*SecurityDescriptor, bool) {
	if v.kind != kindSD {
		return nil, false
	}
	return sdTable.get(uint32(v.bits)), true
}

func (v AttributeValue) String() string {
	switch v.kind {
	case kindString:
		return stringTable.get(uint32(v.bits))
	case kindBool:
		if v.bits != 0 {
			return "true"
		}
		return "false"
	case kindInt:
		return strconv.FormatInt(int64(v.bits), 10)
	case kindFloat:
		return strconv.FormatFloat(math.Float64frombits(v.bits), 'f', -1, 64)
	case kindTime, kindTimeTable:
		t, _ := v.AsTime()
		return t.Format(time.RFC3339Nano)
	case kindSID:
		sid, _ := v.AsSID()
		return sid.String()
	case kindGUID:
		return guidTable.get(uint32(v.bits)).String()
	case kindNode:
		return nodeTable.get(uint32(v.bits)).Label() + " (object)"
	case kindSD:
		return sdTable.get(uint32(v.bits)).StringNoLookup()
	}
	return ""
}

// Raw returns the value as its Go type. It allocates for most kinds; prefer
// the typed As* accessors on hot paths.
func (v AttributeValue) Raw() any {
	switch v.kind {
	case kindString:
		s, _ := v.AsString()
		return s
	case kindBool:
		return v.bits != 0
	case kindInt:
		return int64(v.bits)
	case kindFloat:
		f, _ := v.AsFloat()
		return f
	case kindTime, kindTimeTable:
		t, _ := v.AsTime()
		return t
	case kindSID:
		sid, _ := v.AsSID()
		return sid
	case kindGUID:
		g, _ := v.AsGUID()
		return g
	case kindNode:
		n, _ := v.AsNode()
		return n
	case kindSD:
		sd, _ := v.AsSecurityDescriptor()
		return sd
	}
	return nil
}

func (v AttributeValue) IsZero() bool {
	switch v.kind {
	case kindString:
		return len(stringTable.get(uint32(v.bits))) == 0
	case kindBool, kindInt:
		return v.bits == 0
	case kindFloat:
		f, _ := v.AsFloat()
		return f == 0
	case kindTime, kindTimeTable:
		t, _ := v.AsTime()
		return t.IsZero()
	case kindSID:
		sid, _ := v.AsSID()
		return sid.IsNull()
	case kindGUID:
		return guidTable.get(uint32(v.bits)).IsNil()
	case kindNode:
		return nodeTable.get(uint32(v.bits)).values.Len() == 0
	case kindSD:
		return len(sdTable.get(uint32(v.bits)).DACL.Entries) == 0
	}
	return true
}

func (v AttributeValue) Compare(c AttributeValue) int {
	switch v.kind {
	case kindString:
		if v == c {
			return 0 // Interned: same handle, same string
		}
		return util.CompareStringsCaseInsensitiveUnicodeFast(v.String(), c.String())
	case kindBool:
		if c.kind == kindBool {
			return cmp.Compare(v.bits, c.bits)
		}
	case kindInt:
		switch c.kind {
		case kindInt:
			return cmp.Compare(int64(v.bits), int64(c.bits))
		case kindFloat:
			f, _ := c.AsFloat()
			return cmp.Compare(float64(int64(v.bits)), f)
		}
	case kindFloat:
		f, _ := v.AsFloat()
		switch c.kind {
		case kindFloat:
			g, _ := c.AsFloat()
			return cmp.Compare(f, g)
		case kindInt:
			return cmp.Compare(f, float64(int64(c.bits)))
		}
	case kindTime, kindTimeTable:
		if ct, ok := c.AsTime(); ok {
			t, _ := v.AsTime()
			return t.Compare(ct)
		}
	case kindGUID:
		if c.kind == kindGUID {
			a, b := guidTable.get(uint32(v.bits)), guidTable.get(uint32(c.bits))
			return bytes.Compare(a[:], b[:])
		}
	case kindNode:
		if c.kind == kindNode {
			return cmp.Compare(nodeTable.get(uint32(v.bits)).ID(), nodeTable.get(uint32(c.bits)).ID())
		}
	case kindSD:
		if c.kind == kindSD {
			return bytes.Compare([]byte(sdTable.get(uint32(v.bits)).Raw), []byte(sdTable.get(uint32(c.bits)).Raw))
		}
	}
	return strings.Compare(v.String(), c.String())
}

type AttributeValuePair struct {
	Value1 AttributeValue
	Value2 AttributeValue
}
