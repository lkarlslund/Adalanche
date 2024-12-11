package engine

import (
	"bytes"
	"slices"
	"strconv"
	"strings"
	"time"
	"unique"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func CompareAttributeValues(a, b AttributeValue) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Compare(b) == 0
}

func CompareAttributeValuesInt(a, b AttributeValue) int {
	if a == b {
		return 0
	}
	if a == nil {
		return -1
	} else if b == nil {
		return 1
	}
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
	slices.SortFunc[AttributeValues](avs, CompareAttributeValuesInt)
}

func (avs AttributeValues) First() AttributeValue {
	if len(avs) == 0 {
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

type AttributeValueString unique.Handle[string]

func NewAttributeValueString(s string) AttributeValueString {
	return AttributeValueString(unique.Make(s))
}

func (as AttributeValueString) String() string {
	return unique.Handle[string](as).Value()
}

func (as AttributeValueString) Raw() any {
	return unique.Handle[string](as).Value()
}

func (as AttributeValueString) IsZero() bool {
	return len(unique.Handle[string](as).Value()) == 0
}

func (as AttributeValueString) Compare(c AttributeValue) int {
	if cs, ok := c.(AttributeValueString); ok {
		// Fast path for same string, no need to compare contents again, as unique sorts this out for us
		if unique.Handle[string](as) == unique.Handle[string](cs) {
			return 0
		}
	}
	return strings.Compare(as.String(), c.String())
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

type AttributeValueSID unique.Handle[windowssecurity.SID]

func NewAttributeValueSID(s windowssecurity.SID) AttributeValueSID {
	return AttributeValueSID(unique.Make(s))
}

func (as AttributeValueSID) String() string {
	return unique.Handle[windowssecurity.SID](as).Value().String()
}

func (as AttributeValueSID) Raw() any {
	return unique.Handle[windowssecurity.SID](as).Value()
}

func (as AttributeValueSID) IsZero() bool {
	return unique.Handle[windowssecurity.SID](as).Value().IsNull()
}

func (ab AttributeValueSID) Compare(c AttributeValue) int {
	return strings.Compare(ab.String(), c.String())
}

type AttributeValueGUID unique.Handle[uuid.UUID]

func NewAttributeValueGUID(u uuid.UUID) AttributeValueGUID {
	return AttributeValueGUID(unique.Make(u))
}

func (as AttributeValueGUID) String() string {
	return (unique.Handle[uuid.UUID])(as).Value().String()
}

func (as AttributeValueGUID) Raw() any {
	return (unique.Handle[uuid.UUID])(as).Value()
}

func (as AttributeValueGUID) IsZero() bool {
	return (unique.Handle[uuid.UUID])(as).Value().IsNil()
}

func (ab AttributeValueGUID) Compare(c AttributeValue) int {
	if cb, ok := c.(AttributeValueGUID); ok {
		return bytes.Compare((unique.Handle[uuid.UUID])(ab).Value().Bytes(), (unique.Handle[uuid.UUID])(cb).Value().Bytes())
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
