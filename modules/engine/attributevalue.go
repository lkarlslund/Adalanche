package engine

import (
	"bytes"
	"slices"
	"strconv"
	"strings"
	"time"

	gsync "github.com/SaveTheRbtz/generic-sync-map-go"
	xxhash "github.com/cespare/xxhash/v2"
	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/util"
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
	for i := range avs {
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

var uniqueValues gsync.MapOf[uint64, AttributeValue]

func NV(v any) AttributeValue {
	if v == nil {
		return nil
	}

	var digest xxhash.Digest

	switch val := v.(type) {
	case AttributeValue:
		// assume it's already normalized / deduplicated
		return val
	case string:
		digest.ResetWithSeed(0)
		digest.WriteString(val)
		hash := digest.Sum64()
		existingValue, isCached := uniqueValues.Load(hash)
		if isCached {
			// compare base types
			return existingValue
		}
		newValue := attributeValueString(val)
		existingValue, _ = uniqueValues.LoadOrStore(hash, newValue)
		return existingValue
	case *bool:
		if val == nil {
			return nil
		}
		return attributeValueBool(*val)
	case bool:
		return attributeValueBool(val)
	case int:
		return attributeValueInt(int64(val))
	case int32:
		return attributeValueInt(val)
	case uint32:
		return attributeValueInt(val)
	case int64:
		return attributeValueInt(val)
	case uint64:
		return attributeValueInt(val)
	case time.Time:
		return attributeValueTime(val)
	case windowssecurity.SID:
		// assume it's deduplicated already
		return attributeValueSID(val)
	case uuid.UUID:
		digest.ResetWithSeed(3117)
		digest.Write(val[:])
		hash := digest.Sum64()
		// try to find existing, no allocs
		if existingValue, isCached := uniqueValues.Load(hash); isCached {
			return existingValue
		}
		existingValue, _ := uniqueValues.LoadOrStore(hash, attributeValueGUID(val))
		return existingValue
	case float32:
		return attributeValueFloat(val)
	case float64:
		return attributeValueFloat(val)
	case *Node:
		return attributeValueNode{Node: val}
	case *SecurityDescriptor:
		return attributeValueSecurityDescriptor{SD: val}
	default:
		panic("unsupported attribute value type")
	}
	return nil
}

type AttributeValuePair struct {
	Value1 AttributeValue
	Value2 AttributeValue
}

type attributeValueNode struct {
	*Node
}

func (avo attributeValueNode) String() string {
	return (*Node)(avo.Node).Label() + " (object)"
}

func (avo attributeValueNode) Raw() any {
	return (*Node)(avo.Node)
}

func (avo attributeValueNode) IsZero() bool {
	if avo.Node == nil {
		return true
	}
	return avo.values.Len() == 0
}

func (ab attributeValueNode) Compare(c AttributeValue) int {
	if cb, ok := c.(attributeValueNode); ok {
		return int(ab.ID() - cb.ID())
	}
	return strings.Compare(ab.String(), c.String())
}

type attributeValueString string

func (as attributeValueString) String() string {
	return string(as)
}

func (as attributeValueString) Raw() any {
	return string(as)
}

func (as attributeValueString) IsZero() bool {
	return len(as) == 0
}

func (as attributeValueString) Compare(c AttributeValue) int {
	if cs, ok := c.(attributeValueString); ok {
		// Fast path for same string, no need to compare contents again
		if as == cs {
			return 0
		}
	}
	return util.CompareStringsCaseInsensitiveUnicodeFast(as.String(), c.String())
}

type attributeValueBool bool

func (ab attributeValueBool) String() string {
	if bool(ab) {
		return "true"
	}
	return "false"
}

func (ab attributeValueBool) Raw() any {
	return bool(ab)
}

func (ab attributeValueBool) IsZero() bool {
	return !bool(ab)
}

func (ab attributeValueBool) Compare(c AttributeValue) int {
	if cb, ok := c.(attributeValueBool); ok {
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

type attributeValueInt int64

func (as attributeValueInt) String() string {
	return strconv.FormatInt(int64(as), 10)
}

func (as attributeValueInt) Raw() any {
	return int64(as)
}

func (as attributeValueInt) IsZero() bool {
	return int64(as) == 0
}

func (ab attributeValueInt) Compare(c AttributeValue) int {
	if cb, ok := c.(attributeValueInt); ok {
		return int(ab - cb)
	}
	if cb, ok := c.(attributeValueFloat); ok {
		res := float64(ab) - float64(cb)
		if res < 0 {
			return -1
		} else if res > 0 {
			return 1
		}
		return 0
	}
	return strings.Compare(ab.String(), c.String())
}

type attributeValueFloat float64

func (as attributeValueFloat) String() string {
	return strconv.FormatFloat(float64(as), 'f', -1, 64)
}

func (as attributeValueFloat) Raw() any {
	return float64(as)
}

func (as attributeValueFloat) IsZero() bool {
	return float64(as) == 0
}

func (ab attributeValueFloat) Compare(c AttributeValue) int {
	if cb, ok := c.(attributeValueFloat); ok {
		return int(ab - cb)
	}
	if cb, ok := c.(attributeValueInt); ok {
		res := float64(ab) - float64(cb)
		if res < 0 {
			return -1
		} else if res > 0 {
			return 1
		}
		return 0
	}
	return strings.Compare(ab.String(), c.String())
}

type attributeValueTime time.Time

func (as attributeValueTime) String() string {
	return time.Time(as).Format(time.RFC3339Nano)
}

func (as attributeValueTime) Raw() any {
	return time.Time(as)
}

func (as attributeValueTime) IsZero() bool {
	return time.Time(as).IsZero()
}

func (ab attributeValueTime) Compare(c AttributeValue) int {
	if cb, ok := c.Raw().(time.Time); ok {
		return int(time.Time(ab).Sub(cb))
	}
	return strings.Compare(ab.String(), c.String())
}

type attributeValueSID windowssecurity.SID

func (as attributeValueSID) String() string {
	return windowssecurity.SID(as).String()
}

func (as attributeValueSID) Raw() any {
	return windowssecurity.SID(as)
}

func (as attributeValueSID) IsZero() bool {
	return windowssecurity.SID(as).IsNull()
}

func (ab attributeValueSID) Compare(c AttributeValue) int {
	return strings.Compare(ab.String(), c.String())
}

type attributeValueGUID uuid.UUID

func (as attributeValueGUID) String() string {
	return uuid.UUID(as).String()
}

func (as attributeValueGUID) Raw() any {
	return uuid.UUID(as)
}

func (as attributeValueGUID) IsZero() bool {
	return uuid.UUID(as).IsNil()
}

func (ab attributeValueGUID) Compare(c AttributeValue) int {
	if cb, ok := c.(attributeValueGUID); ok {
		return bytes.Compare(uuid.UUID(ab).Bytes(), uuid.UUID(cb).Bytes())
	}
	return strings.Compare(ab.String(), c.String())
}

type attributeValueSecurityDescriptor struct {
	SD *SecurityDescriptor
}

func (as attributeValueSecurityDescriptor) String() string {
	return as.SD.StringNoLookup()
}

func (as attributeValueSecurityDescriptor) Raw() any {
	return as.SD
}

func (as attributeValueSecurityDescriptor) IsZero() bool {
	return len(as.SD.DACL.Entries) == 0
}

func (ab attributeValueSecurityDescriptor) Compare(c AttributeValue) int {
	if cb, ok := c.(attributeValueSecurityDescriptor); ok {
		return bytes.Compare([]byte(ab.SD.Raw), []byte(cb.SD.Raw))
	}
	return strings.Compare(ab.String(), c.String())
}
