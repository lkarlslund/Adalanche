package engine

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/rs/zerolog/log"
)

func CompareAttributeValues(a, b AttributeValue) bool {
	araw := a.Raw()
	braw := b.Raw()
	switch na := araw.(type) {
	case bool:
		nb, btype := braw.(bool)
		if btype {
			return na == nb
		}
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
			return bytes.Equal(na, nb)
		}
	case windowssecurity.SID:
		nb, btype := braw.(windowssecurity.SID)
		if btype {
			return string(na) == string(nb)
		}
	case uuid.UUID:
		nb, btype := braw.(uuid.UUID)
		if btype {
			return na == nb
		}
	case *Object:
		nb, btype := braw.(*Object)
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
	Slice() []AttributeValue
	StringSlice() []string
	Len() int
}

type NoValues struct{}

func (nv NoValues) Slice() []AttributeValue {
	return nil
}

func (nv NoValues) StringSlice() []string {
	return nil
}

func (nv NoValues) Len() int {
	return 0
}

func AttributeValueSliceFromStrings(values []string) AttributeValueSlice {
	var result AttributeValueSlice
	for _, av := range values {
		result = append(result, AttributeValueString(av))
	}
	return result
}

type AttributeValueSlice []AttributeValue

func (avs AttributeValueSlice) Slice() []AttributeValue {
	return avs
}

func (avs AttributeValueSlice) StringSlice() []string {
	result := make([]string, len(avs))
	for i := 0; i < len(avs); i++ {
		if avs[i] == nil {
			log.Warn().Msg("Encountered NIL value")
		} else {
			result[i] = avs[i].String()
		}
	}
	return result
}

func (avs AttributeValueSlice) Len() int {
	return len(avs)
}

type AttributeValueOne struct {
	Value AttributeValue
}

func (avo AttributeValueOne) Len() int {
	return 1
}

func (avo AttributeValueOne) Slice() []AttributeValue {
	return AttributeValueSlice{avo.Value}
}

func (avo AttributeValueOne) StringSlice() []string {
	return []string{avo.Value.String()}
}

type AttributeValue interface {
	String() string
	Raw() interface{}
	IsZero() bool
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
	return len(avo.values) == 0
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

type AttributeValueBlob []byte

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

// type AttributeValueFiletime []byte

// func (as AttributeValueFiletime) String() string {
// 	return string(as)
// }

// func (as AttributeValueFiletime) Raw() interface{} {
// 	return string(as)
// }

// func (as AttributeValueFiletime) AsTime() time.Time {
// 	return nil
// }
