package engine

import (
	"bytes"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func CompareAttributeValues(a, b AttributeValue) bool {
	araw := a.Raw()
	braw := b.Raw()
	switch na := araw.(type) {
	case string:
		nb, btype := braw.(string)
		if btype {
			return strings.EqualFold(na, nb)
		}
	case int64:
		nb, btype := braw.(int64)
		if btype {
			return na == nb
		}
	case time.Time:
		nb, btype := braw.(time.Time)
		if btype {
			return na.Equal(nb)
		}
	case []byte:
		nb, btype := braw.([]byte)
		if btype {
			return bytes.Compare(na, nb) == 0
		}
	case windowssecurity.SID:
		nb, btype := braw.(windowssecurity.SID)
		if btype {
			return na == nb
		}
	}

	// Fallback
	return a.String() == b.String()
}

type AttributeAndValues struct {
	Attribute
	AttributeValues
}

// AttributeValues can contain one or more values
type AttributeValues interface {
	Slice() []AttributeValue
	StringSlice() []string
	Len() int
}

type NoValues struct{}

func (nv NoValues) Slice() []AttributeValue {
	return []AttributeValue{}
}

func (nv NoValues) StringSlice() []string {
	return []string{}
}

func (nv NoValues) Len() int {
	return 0
}

type AttributeValueSlice []AttributeValue

func (avs AttributeValueSlice) Slice() []AttributeValue {
	return avs
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
	AttributeValue
}

func (avo AttributeValueOne) Len() int {
	return 1
}

func (avo AttributeValueOne) Slice() []AttributeValue {
	return AttributeValueSlice{avo.AttributeValue}
}

func (avo AttributeValueOne) StringSlice() []string {
	return []string{avo.AttributeValue.String()}
}

type AttributeValue interface {
	String() string
	Raw() interface{}
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

type AttributeValueString string

func (as AttributeValueString) String() string {
	return string(as)
}

func (as AttributeValueString) Raw() interface{} {
	return string(as)
}

type AttributeValueInt int64

func (as AttributeValueInt) String() string {
	return strconv.FormatInt(int64(as), 10)
}

func (as AttributeValueInt) Raw() interface{} {
	return int64(as)
}

type AttributeValueTime time.Time

func (as AttributeValueTime) String() string {
	return time.Time(as).Format("20060102150405")
}

func (as AttributeValueTime) Raw() interface{} {
	return time.Time(as)
}

type AttributeValueSID windowssecurity.SID

func (as AttributeValueSID) String() string {
	return windowssecurity.SID(as).String()
}

func (as AttributeValueSID) Raw() interface{} {
	return windowssecurity.SID(as)
}

type AttributeValueGUID uuid.UUID

func (as AttributeValueGUID) String() string {
	return (uuid.UUID)(as).String()
}

func (as AttributeValueGUID) Raw() interface{} {
	return uuid.UUID(as)
}

type AttributeValueFiletime []byte

func (as AttributeValueFiletime) String() string {
	return string(as)
}

func (as AttributeValueFiletime) Raw() interface{} {
	return string(as)
}

// func (as AttributeValueFiletime) AsTime() time.Time {
// 	return nil
// }
