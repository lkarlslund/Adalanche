package main

import (
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	ldap "github.com/lkarlslund/ldap/v3"
	"github.com/lkarlslund/stringdedup"
	"github.com/rs/zerolog/log"
)

//go:generate msgp

type RawObject struct {
	DistinguishedName string
	Attributes        map[string][]string
}

func (r *RawObject) init() {
	r.DistinguishedName = ""
	r.Attributes = make(map[string][]string)
}

func (r *RawObject) ToObject(importall bool) *Object {
	result := NewObject(
		DistinguishedName, AttributeValueString(stringdedup.S(r.DistinguishedName)),
	) // This is possibly repeated in member attributes, so dedup it
	for name, values := range r.Attributes {
		if len(values) == 0 || (len(values) == 1 && values[0] == "") {
			continue
		}
		attribute := NewAttribute(name)
		// do we even want this?
		if !importall && attribute > MAX_IMPORTED && !strings.HasPrefix(name, "_") {
			continue
		}

		avs := make(AttributeValueSlice, len(values))
		var skipped int

		for valindex, value := range values {
			// statistics
			attributesizes[attribute] += len(value)

			var attributevalue AttributeValue
			switch attribute {
			// Add more things here, like time decoding etc
			case AttributeSecurityGUID, SchemaIDGUID:
				guid, err := uuid.FromBytes([]byte(value))
				if err == nil {
					guid = SwapUUIDEndianess(guid)
					attributevalue = AttributeValueGUID(guid)
				} else {
					log.Warn().Msgf("Failed to convert attribute %v value %2x to GUID: %v", attribute.String(), []byte(value), err)
				}
			case RightsGUID:
				guid, err := uuid.FromString(value)
				if err == nil {
					guid = SwapUUIDEndianess(guid)
					attributevalue = AttributeValueGUID(guid)
				} else {
					log.Warn().Msgf("Failed to convert attribute %v value %2x to GUID: %v", attribute.String(), []byte(value), err)
				}
			case ObjectGUID:
				guid, err := uuid.FromBytes([]byte(value))
				if err == nil {
					// 	guid = SwapUUIDEndianess(guid)
					attributevalue = AttributeValueGUID(guid)
				} else {
					log.Warn().Msgf("Failed to convert attribute %v value %2x to GUID: %v", attribute.String(), []byte(value), err)
				}
			case ObjectCategory:
				attributevalue = AttributeValueRenderedObjectClass(value)
			case ObjectSid:
				attributevalue = AttributeValueSID(value)
			case NTSecurityDescriptor:
				if err := result.cacheSecurityDescriptor([]byte(value)); err != nil {
					log.Error().Msgf("Problem parsing security descriptor for %v: %v", result.DN(), err)
				}
				fallthrough
			default:
				// Just use string encoding
				if intval, err := strconv.ParseInt(value, 10, 64); err == nil {
					attributevalue = AttributeValueInt(intval)
				}
				if attributevalue == nil {
					// Lets try as a timestamp
					if strings.HasSuffix(value, "Z") { // "20171111074031.0Z"
						tvalue := strings.TrimSuffix(value, "Z")  // strip "Z"
						tvalue = strings.TrimSuffix(tvalue, ".0") // strip ".0"
						if t, err := time.Parse("20060102150405", value); err == nil {
							attributevalue = AttributeValueTime(t)
						}
					}
				}
				if attributevalue == nil {
					// Just a string
					attributevalue = AttributeValueString(stringdedup.S(value))
				}
			}

			if attributevalue != nil {
				avs[valindex-skipped] = attributevalue
			} else {
				skipped++
			}
		}
		result.SetAttr(attribute, avs[:len(values)-skipped]...)
	}
	return result
}

func (r *RawObject) IngestLDAP(source *ldap.Entry) error {
	r.init()
	// if len(source.Attributes) == 0 {
	// 	return errors.New("No attributes in object, ignoring")
	// }
	r.DistinguishedName = source.DN
	for _, attr := range source.Attributes {
		r.Attributes[attr.Name] = attr.Values
	}
	return nil
}
