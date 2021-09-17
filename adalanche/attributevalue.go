package main

import (
	"strconv"
	"time"

	"github.com/gofrs/uuid"
)

type AttributeValues interface {
	Slice() []AttributeValue
	StringSlice() []string
	Len() int
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

type AttributeValueSID SID

func (as AttributeValueSID) String() string {
	return SID(as).String()
}

func (as AttributeValueSID) Raw() interface{} {
	return SID(as)
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
