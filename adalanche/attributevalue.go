package main

import (
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
)

type AttributeValues []AttributeValue

func (avs AttributeValues) StringSlice() []string {
	result := make([]string, len(avs))
	for i := 0; i < len(avs); i++ {
		result[i] = avs[i].String()
	}
	return result
}

type AttributeValue interface {
	String() string
	Raw() interface{}
}

type AttributeValueRenderer interface {
	Render() string
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

type AttributeValueRenderedObjectClass AttributeValueString

func (avro AttributeValueRenderedObjectClass) String() string {
	return string(avro)
}

func (avro AttributeValueRenderedObjectClass) Raw() interface{} {
	return string(avro)
}

func (avro AttributeValueRenderedObjectClass) Render() string {
	value := avro.String()
	firstcomma := strings.Index(value, ",")
	if firstcomma > 3 {
		return value[3:firstcomma]
	}
	return value
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
