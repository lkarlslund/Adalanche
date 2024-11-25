package engine

import (
	"bytes"
	"fmt"
	"slices"
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
		if a == nil || b == nil {
			return a == b
		}
		return a.String() == b.String()
	}

	return false
}

func CompareAttributeValuesInt(a, b AttributeValue) int {
	return a.Compare(b)
}

type AttributeAndValues struct {
	values    AttributeValues
	attribute Attribute
}

// AttributeValues can contain one or more values
type AttributeValues []AttributeValue

func (avs AttributeValues) Sort() {
	if avs == nil {
		return
	}
	slices.SortFunc[AttributeValues](avs, func(a, b AttributeValue) int {
		return a.Compare(b)
	})
}

func (avs AttributeValues) First() AttributeValue {
	if avs == nil {
		return nil
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
	for i := 0; i < len(avs); i++ {
		result[i] = avs[i].String()
	}
	return result
}

func (avs AttributeValues) Len() int {
	return len(avs)
}

type AttributeValue interface {
	String() string
	Raw() any
	IsZero() bool
	Compare(AttributeValue) int
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

func (avo AttributeValueObject) Raw() any {
	return (*Object)(avo.Object)
}

func (avo AttributeValueObject) IsZero() bool {
	if avo.Object == nil {
		return true
	}
	return avo.values.Len() == 0
}

func (ab AttributeValueObject) Compare(c AttributeValue) int {
	if cb, ok := c.(AttributeValueObject); ok {
		return int(ab.ID() - cb.ID())
	}
	return strings.Compare(ab.String(), c.String())
}

type AttributeValueString string

func (as AttributeValueString) String() string {
	return string(as)
}

func (as AttributeValueString) Raw() any {
	return string(as)
}

func (as AttributeValueString) IsZero() bool {
	return len(as) == 0
}

func (as AttributeValueString) Compare(c AttributeValue) int {
	return strings.Compare(string(as), c.String())
}

type AttributeValueBlob string

func (ab AttributeValueBlob) String() string {
	return fmt.Sprintf("% x", []byte(ab))
}

func (ab AttributeValueBlob) Raw() any {
	return []byte(ab)
}

func (ab AttributeValueBlob) IsZero() bool {
	return len(ab) == 0
}

func (ab AttributeValueBlob) Compare(c AttributeValue) int {
	if cb, ok := c.(AttributeValueBlob); ok {
		return bytes.Compare([]byte(ab), []byte(cb))
	}
	return strings.Compare(ab.String(), c.String())
}

type AttributeValueBool bool

func (ab AttributeValueBool) String() string {
	if bool(ab) {
		return "true"
	}
	return "false"
}

func (ab AttributeValueBool) Raw() any {
	return bool(ab)
}

func (ab AttributeValueBool) IsZero() bool {
	return !bool(ab)
}

func (ab AttributeValueBool) Compare(c AttributeValue) int {
	if cb, ok := c.(AttributeValueBool); ok {
		if ab == cb {
			return 0
		}
		if ab == false {
			return -1
		}
		return 1
	}
	return strings.Compare(ab.String(), c.String())
}

type AttributeValueInt int64

func (as AttributeValueInt) String() string {
	return strconv.FormatInt(int64(as), 10)
}

func (as AttributeValueInt) Raw() any {
	return int64(as)
}

func (as AttributeValueInt) IsZero() bool {
	return int64(as) == 0
}

func (ab AttributeValueInt) Compare(c AttributeValue) int {
	if cb, ok := c.(AttributeValueInt); ok {
		return int(ab - cb)
	}
	return strings.Compare(ab.String(), c.String())
}

type AttributeValueTime time.Time

func (as AttributeValueTime) String() string {
	return time.Time(as).Format("20060102150405")
}

func (as AttributeValueTime) Raw() any {
	return time.Time(as)
}

func (as AttributeValueTime) IsZero() bool {
	return time.Time(as).IsZero()
}

func (ab AttributeValueTime) Compare(c AttributeValue) int {
	if cb, ok := c.(AttributeValueTime); ok {
		return int(time.Time(ab).Sub(time.Time(cb)))
	}
	return strings.Compare(ab.String(), c.String())
}

type AttributeValueSID windowssecurity.SID

func (as AttributeValueSID) String() string {
	return windowssecurity.SID(as).String()
}

func (as AttributeValueSID) Raw() any {
	return windowssecurity.SID(as)
}

func (as AttributeValueSID) IsZero() bool {
	return windowssecurity.SID(as).IsNull()
}

func (ab AttributeValueSID) Compare(c AttributeValue) int {
	if cb, ok := c.(AttributeValueSID); ok {
		return bytes.Compare([]byte(ab), []byte(cb))
	}
	return strings.Compare(ab.String(), c.String())
}

type AttributeValueGUID uuid.UUID

func (as AttributeValueGUID) String() string {
	return (uuid.UUID)(as).String()
}

func (as AttributeValueGUID) Raw() any {
	return uuid.UUID(as)
}

func (as AttributeValueGUID) IsZero() bool {
	return uuid.UUID(as).IsNil()
}

func (ab AttributeValueGUID) Compare(c AttributeValue) int {
	if cb, ok := c.(AttributeValueGUID); ok {
		return bytes.Compare(ab[:], cb[:])
	}
	return strings.Compare(ab.String(), c.String())
}

type AttributeValueSecurityDescriptor struct {
	SD *SecurityDescriptor
}

func (as AttributeValueSecurityDescriptor) String() string {
	return as.SD.StringNoLookup()
}

func (as AttributeValueSecurityDescriptor) Raw() any {
	return as.SD
}

func (as AttributeValueSecurityDescriptor) IsZero() bool {
	return len(as.SD.DACL.Entries) == 0
}

func (ab AttributeValueSecurityDescriptor) Compare(c AttributeValue) int {
	if cb, ok := c.(AttributeValueSecurityDescriptor); ok {
		return bytes.Compare([]byte(ab.SD.Raw), []byte(cb.SD.Raw))
	}
	return strings.Compare(ab.String(), c.String())
}
