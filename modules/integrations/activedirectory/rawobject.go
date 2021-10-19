package activedirectory

import (
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/util"
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

func (r *RawObject) ToObject(importall bool) *engine.Object {
	result := engine.NewObject(
		engine.DistinguishedName, engine.AttributeValueString(stringdedup.S(r.DistinguishedName)),
	) // This is possibly repeated in member attributes, so dedup it
	for name, values := range r.Attributes {
		if len(values) == 0 || (len(values) == 1 && values[0] == "") {
			continue
		}
		attribute := engine.NewAttribute(name)
		// do we even want this?
		if !importall && attribute > engine.MAX_IMPORTED && !strings.HasPrefix(name, "_") {
			continue
		}

		result.SetAttr(attribute, EncodeAttributeData(attribute, values)...)
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

func EncodeAttributeData(attribute engine.Attribute, values []string) engine.AttributeValueSlice {
	avs := make(engine.AttributeValueSlice, len(values))

	var skipped int

	for valindex, value := range values {
		var attributevalue engine.AttributeValue
		switch attribute {
		// Add more things here, like time decoding etc
		case engine.AttributeSecurityGUID, engine.SchemaIDGUID, engine.MSDSConsistencyGUID:
			guid, err := uuid.FromBytes([]byte(value))
			if err == nil {
				guid = util.SwapUUIDEndianess(guid)
				attributevalue = engine.AttributeValueGUID(guid)
			} else {
				log.Warn().Msgf("Failed to convert attribute %v value %2x to GUID: %v", attribute.String(), []byte(value), err)
			}
		case engine.RightsGUID:
			guid, err := uuid.FromString(value)
			if err == nil {
				guid = util.SwapUUIDEndianess(guid)
				attributevalue = engine.AttributeValueGUID(guid)
			} else {
				log.Warn().Msgf("Failed to convert attribute %v value %2x to GUID: %v", attribute.String(), []byte(value), err)
			}
		case engine.ObjectGUID:
			guid, err := uuid.FromBytes([]byte(value))
			if err == nil {
				// 	guid = SwapUUIDEndianess(guid)
				attributevalue = engine.AttributeValueGUID(guid)
			} else {
				log.Warn().Msgf("Failed to convert attribute %v value %2x to GUID: %v", attribute.String(), []byte(value), err)
			}
		case engine.ObjectCategory:
			attributevalue = engine.AttributeValueString(value)
		case engine.ObjectSid:
			attributevalue = engine.AttributeValueSID(value)
			fallthrough
		default:
			// Just use string encoding
			if intval, err := strconv.ParseInt(value, 10, 64); err == nil {
				attributevalue = engine.AttributeValueInt(intval)
			}
			if attributevalue == nil {
				// Lets try as a timestamp
				if strings.HasSuffix(value, "Z") { // "20171111074031.0Z"
					tvalue := strings.TrimSuffix(value, "Z")  // strip "Z"
					tvalue = strings.TrimSuffix(tvalue, ".0") // strip ".0"
					if t, err := time.Parse("20060102150405", tvalue); err == nil {
						attributevalue = engine.AttributeValueTime(t)
					}
				}
			}
			if attributevalue == nil {
				// Just a string
				attributevalue = engine.AttributeValueString(stringdedup.S(value))
			}
		}

		if attributevalue != nil {
			avs[valindex-skipped] = attributevalue
		} else {
			skipped++
		}
	}
	return avs[:len(values)-skipped]
}
