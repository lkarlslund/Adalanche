package engine

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func CompareAttributeValues(a, b AttributeValue) bool {
	switch na := a.(type) {
	case AttributeValueBool:
		nb, btype := b.(AttributeValueBool)
		if btype {
			return na == nb
		}
	case AttributeValueString:
		nb, btype := b.(AttributeValueString)
		if btype {
			return strings.EqualFold(string(na), string(nb))
		}
	case AttributeValueInt:
		nb, btype := b.(AttributeValueInt)
		if btype {
			return na == nb
		}
	case AttributeValueTime:
		nb, btype := b.(AttributeValueTime)
		if btype {
			return time.Time(na).Equal(time.Time(nb))
		}
	case AttributeValueBlob:
		nb, btype := b.(AttributeValueBlob)
		if btype {
			return bytes.Equal([]byte(na), []byte(nb))
		}
	case AttributeValueSID:
		nb, btype := b.(AttributeValueSID)
		if btype {
			return string(na) == string(nb)
		}
	case AttributeValueGUID:
		nb, btype := b.(AttributeValueGUID)
		if btype {
			return na == nb
		}
	case AttributeValueObject:
		nb, btype := b.(AttributeValueObject)
		if btype {
			return na == nb // Exact same object pointed to in memory
		}
	default:
		// Fallback
		return a.String() == b.String()
	}

	return false
}

type AttributeAndValues struct {
	AttributeValues
	Attribute
}

// AttributeValues can contain one or more values
type AttributeValues interface {
	First() AttributeValue
	Iterate(func(val AttributeValue) bool)
	StringSlice() []string
	Len() int
}

type NoValues struct{}

func (nv NoValues) First() AttributeValue {
	return nil
}

func (nv NoValues) Iterate(func(val AttributeValue) bool) {
	// no op
}

func (nv NoValues) Slice() []AttributeValue {
	return nil
}

func (nv NoValues) StringSlice() []string {
	return nil
}

func (nv NoValues) Len() int {
	return 0
}

type AttributeValueSlice []AttributeValue

func (avs AttributeValueSlice) First() AttributeValue {
	return avs[0]
}

func (avs AttributeValueSlice) Iterate(it func(val AttributeValue) bool) {
	for _, cval := range avs {
		if !it(cval) {
			break
		}
	}
}

func (avs AttributeValueSlice) StringSlice() []string {
	result := make([]string, len(avs))
	for i := 0; i < len(avs); i++ {
		result[i] = avs[i].String()
	}
	return result
}

func (avs AttributeValueSlice) Len() int {
	return len(avs)
}

type AttributeValueOne struct {
	Value AttributeValue
}

func (avo AttributeValueOne) First() AttributeValue {
	return avo.Value
}

func (avo AttributeValueOne) Iterate(it func(val AttributeValue) bool) {
	it(avo.Value)
}

func (avo AttributeValueOne) Len() int {
	return 1
}

func (avo AttributeValueOne) StringSlice() []string {
	return []string{avo.Value.String()}
}

type AttributeValue interface {
	String() string
	Raw() interface{}
	IsZero() bool
}

type AttributeValuePair struct {
	Value1 AttributeValue
	Value2 AttributeValue
}

type AttributeValueObject struct {
	*Object
}

func (avo AttributeValueObject) String() string {
	return (*Object)(avo.Object).Label() + " (object)"
}

func (avo AttributeValueObject) Raw() interface{} {
	return (*Object)(avo.Object)
}

func (avo AttributeValueObject) IsZero() bool {
	if avo.Object == nil {
		return true
	}
	return avo.values.Len() == 0
}

type AttributeValueString string

func (as AttributeValueString) String() string {
	return string(as)
}

func (as AttributeValueString) Raw() interface{} {
	return string(as)
}

func (as AttributeValueString) IsZero() bool {
	return len(as) == 0
}

type AttributeValueBlob string

func (ab AttributeValueBlob) String() string {
	return fmt.Sprintf("% x", []byte(ab))
}

func (ab AttributeValueBlob) Raw() interface{} {
	return []byte(ab)
}

func (ab AttributeValueBlob) IsZero() bool {
	return len(ab) == 0
}

type AttributeValueBool bool

func (ab AttributeValueBool) String() string {
	if bool(ab) {
		return "true"
	}
	return "false"
}

func (ab AttributeValueBool) Raw() interface{} {
	return bool(ab)
}

func (ab AttributeValueBool) IsZero() bool {
	return !bool(ab)
}

type AttributeValueInt int64

func (as AttributeValueInt) String() string {
	return strconv.FormatInt(int64(as), 10)
}

func (as AttributeValueInt) Raw() interface{} {
	return int64(as)
}

func (as AttributeValueInt) IsZero() bool {
	return int64(as) == 0
}

type AttributeValueTime time.Time

func (as AttributeValueTime) String() string {
	return time.Time(as).Format("20060102150405")
}

func (as AttributeValueTime) Raw() interface{} {
	return time.Time(as)
}

func (as AttributeValueTime) IsZero() bool {
	return time.Time(as).IsZero()
}

type AttributeValueSID windowssecurity.SID

func (as AttributeValueSID) String() string {
	return windowssecurity.SID(as).String()
}

func (as AttributeValueSID) Raw() interface{} {
	return windowssecurity.SID(as)
}

func (as AttributeValueSID) IsZero() bool {
	return windowssecurity.SID(as).IsNull()
}

type AttributeValueGUID uuid.UUID

func (as AttributeValueGUID) String() string {
	return (uuid.UUID)(as).String()
}

func (as AttributeValueGUID) Raw() interface{} {
	return uuid.UUID(as)
}

func (as AttributeValueGUID) IsZero() bool {
	return uuid.UUID(as).IsNil()
}
