package activedirectory

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/util"
	ldap "github.com/lkarlslund/ldap/v3"
	"github.com/rs/zerolog/log"
)

//go:generate msgp

type RawObject struct {
	DistinguishedName string
	Attributes        map[string][]string
}

func (r *RawObject) Init() {
	r.DistinguishedName = ""
	r.Attributes = make(map[string][]string)
}

func (r *RawObject) ToObject(onlyKnownAttributes bool) *engine.Object {
	result := engine.NewObject(
		DistinguishedName, engine.AttributeValueString(r.DistinguishedName),
	) // This is possibly repeated in member attributes, so dedup it
	for name, values := range r.Attributes {
		if len(values) == 0 || (len(values) == 1 && values[0] == "") {
			continue
		}

		var attribute engine.Attribute
		if onlyKnownAttributes {
			attribute = engine.LookupAttribute(name)
			if attribute == engine.NonExistingAttribute {
				continue
			}
		} else {
			attribute = engine.NewAttribute(name)
		}

		encodedvals := EncodeAttributeData(attribute, values)
		if encodedvals != nil {
			result.Set(attribute, encodedvals)
		}
	}

	return result
}

func (r *RawObject) IngestLDAP(source *ldap.Entry) error {
	r.Init()
	r.DistinguishedName = source.DN
	for _, attr := range source.Attributes {
		r.Attributes[attr.Name] = attr.Values
	}
	return nil
}

// Performance hack
var avsPool sync.Pool

func init() {
	avsPool.New = func() interface{} {
		return make(engine.AttributeValueSlice, 0, 16)
	}
}

func EncodeAttributeData(attribute engine.Attribute, values []string) engine.AttributeValues {
	if len(values) == 0 {
		return nil
	}

	avs := avsPool.Get().(engine.AttributeValueSlice)

	var skipped int

	for _, value := range values {
		var attributevalue engine.AttributeValue
		switch attribute {
		// Add more things here, like time decoding etc
		case AccountExpires, PwdLastSet, LastLogon, LastLogonTimestamp, MSmcsAdmPwdExpirationTime:
			// Just use string encoding
			if intval, err := strconv.ParseInt(value, 10, 64); err == nil {
				if attribute == PwdLastSet && intval == 0 {
					// log.Warn().Msg("PwdLastSet is 0")
					attributevalue = engine.AttributeValueInt(intval)
				} else {
					t := util.FiletimeToTime(uint64(intval))
					attributevalue = engine.AttributeValueTime(t)
				}
			} else {
				log.Warn().Msgf("Failed to convert attribute %v value %2x to timestamp: %v", attribute.String(), value, err)
			}
		case WhenChanged, WhenCreated, DsCorePropagationData,
			MsExchLastUpdateTime, MsExchPolicyLastAppliedTime, MsExchWhenMailboxCreated,
			GWARTLastModified, SpaceLastComputed:

			tvalue := strings.TrimSuffix(value, "Z")  // strip "Z"
			tvalue = strings.TrimSuffix(tvalue, ".0") // strip ".0"
			switch len(tvalue) {
			case 14:
				if t, err := time.Parse("20060102150405", tvalue); err == nil {
					attributevalue = engine.AttributeValueTime(t)
				} else {
					log.Warn().Msgf("Failed to convert attribute %v value %2x to timestamp: %v", attribute.String(), tvalue, err)
				}
			case 12:
				if t, err := time.Parse("060102150405", tvalue); err == nil {
					attributevalue = engine.AttributeValueTime(t)
				} else {
					log.Warn().Msgf("Failed to convert attribute %v value %2x to timestamp: %v", attribute.String(), tvalue, err)
				}
			default:
				log.Warn().Msgf("Failed to convert attribute %v value %2x to timestamp (unsupported length): %v", attribute.String(), tvalue)
			}
		case AttributeSecurityGUID, SchemaIDGUID, MSDSConsistencyGUID:
			switch len(value) {
			case 16:
				guid, err := uuid.FromBytes([]byte(value))
				if err == nil {
					guid = util.SwapUUIDEndianess(guid)
					attributevalue = engine.AttributeValueGUID(guid)
				} else {
					log.Warn().Msgf("Failed to convert attribute %v value %2x to GUID: %v", attribute.String(), []byte(value), err)
				}
			case 36:
				guid, err := uuid.FromString(value)
				if err == nil {
					guid = util.SwapUUIDEndianess(guid) // Unsure if this is needed
					attributevalue = engine.AttributeValueGUID(guid)
				} else {
					log.Warn().Msgf("Failed to convert attribute %v value %2x to GUID: %v", attribute.String(), value, err)
				}
			}
		case RightsGUID:
			guid, err := uuid.FromString(value)
			if err == nil {
				guid = util.SwapUUIDEndianess(guid)
				attributevalue = engine.AttributeValueGUID(guid)
			} else {
				log.Warn().Msgf("Failed to convert attribute %v value %2x to GUID: %v", attribute.String(), []byte(value), err)
			}
		case ObjectGUID:
			guid, err := uuid.FromBytes([]byte(value))
			if err == nil {
				// 	guid = SwapUUIDEndianess(guid)
				attributevalue = engine.AttributeValueGUID(guid)
			} else {
				log.Warn().Msgf("Failed to convert attribute %v value %2x to GUID: %v", attribute.String(), []byte(value), err)
			}
		case ObjectSid, SIDHistory, SecurityIdentifier, CreatorSID:
			attributevalue = engine.AttributeValueSID(value)
		default:
			// AUTO CONVERSION - WHAT COULD POSSIBLY GO WRONG
			if value == "true" || value == "TRUE" {
				attributevalue = engine.AttributeValueBool(true)
				break
			} else if value == "false" || value == "FALSE" {
				attributevalue = engine.AttributeValueBool(true)
				break
			}

			if strings.HasSuffix(value, "Z") { // "20171111074031.0Z"
				// Lets try as a timestamp
				tvalue := strings.TrimSuffix(value, "Z")  // strip "Z"
				tvalue = strings.TrimSuffix(tvalue, ".0") // strip ".0"
				if t, err := time.Parse("20060102150405", tvalue); err == nil {
					attributevalue = engine.AttributeValueTime(t)
					break
				}
			}

			// Integer
			if intval, err := strconv.ParseInt(value, 10, 64); err == nil {
				attributevalue = engine.AttributeValueInt(intval)
				break
			}

			// Just a string
			attributevalue = engine.AttributeValueString(value)
		}

		if attributevalue != nil {
			avs = append(avs, attributevalue)
		} else {
			skipped++
		}
	}

	var result engine.AttributeValues

	switch len(avs) {
	case 0:
		return nil
	case 1:
		result = engine.AttributeValueOne{avs[0]}
	default:
		new := make(engine.AttributeValueSlice, len(avs))
		copy(new, avs)
		result = new
	}

	avsPool.Put(avs[:0])
	return result
}
