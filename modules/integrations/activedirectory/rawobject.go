package activedirectory

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	ldap "github.com/lkarlslund/ldap/v3"
)

//go:generate go tool github.com/tinylib/msgp

type RawObject struct {
	Attributes        map[string][]string
	DistinguishedName string
}

func (r *RawObject) Init() {
	r.DistinguishedName = ""
	r.Attributes = make(map[string][]string)
}

func (r *RawObject) ToObject(onlyKnownAttributes bool) *engine.Node {
	newobject := engine.NewNode()

	newobject.SetFlex(
		DistinguishedName, engine.NV(r.DistinguishedName),
	) // This is possibly repeated in member attributes, so dedup it

	// Reusable slice
	var convertedvalues []engine.AttributeValue
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

		convertedvalues = EncodeAttributeData(attribute, convertedvalues, values)
		if len(convertedvalues) > 0 {
			newobject.Set(attribute, convertedvalues...)
		}
	}

	return newobject
}

func (item *RawObject) IngestLDAP(source *ldap.Entry) error {
	item.Init()
	item.DistinguishedName = source.DN
	if len(source.Attributes) == 0 {
		ui.Warn().Msgf("No attribute data for %v", source.DN)
	}
	for _, attr := range source.Attributes {
		if len(attr.Values) == 0 && attr.Name != "member" {
			ui.Warn().Msgf("Object %v attribute %v has no values", item.DistinguishedName, attr.Name)
		}
		item.Attributes[attr.Name] = attr.Values
	}
	return nil
}

func EncodeAttributeData(attribute engine.Attribute, destination []engine.AttributeValue, values []string) []engine.AttributeValue {
	if len(values) == 0 {
		return destination[:0]
	}

	var skipped int

	if cap(destination) < len(values) {
		destination = make(engine.AttributeValues, 0, len(values))
	} else {
		destination = destination[:0]
	}

	for _, value := range values {
		var attributevalue engine.AttributeValue
		switch attribute {
		// Add more things here, like time decoding etc
		case MsPKIRoamingTimeStamp:
			// https://www.sysadmins.lv/blog-en/how-to-convert-ms-pki-roaming-timestamp-attribute.aspx
			t := util.FiletimeToTime(binary.LittleEndian.Uint64([]byte(value[8:])))
			attributevalue = engine.NV(t)
		case AccountExpires, CreationTime, PwdLastSet, LastLogon, LastLogonTimestamp, MSmcsAdmPwdExpirationTime, MSLAPSPasswordExpirationTime, BadPasswordTime:
			if intval, err := strconv.ParseInt(value, 10, 64); err == nil {
				if intval == 0 {
					attributevalue = engine.NV(intval)
				} else {
					t := util.FiletimeToTime(uint64(intval))
					attributevalue = engine.NV(t)
				}
			} else {
				ui.Warn().Msgf("Failed to convert attribute %v value %2x to timestamp: %v", attribute.String(), value, err)
			}
		case WhenChanged, WhenCreated, DsCorePropagationData,
			MsExchLastUpdateTime, MsExchPolicyLastAppliedTime, MsExchWhenMailboxCreated,
			GWARTLastModified, SpaceLastComputed:

			tvalue := strings.TrimSuffix(value, "Z")  // strip "Z"
			tvalue = strings.TrimSuffix(tvalue, ".0") // strip ".0"
			switch len(tvalue) {
			case 14:
				if t, err := time.Parse("20060102150405", tvalue); err == nil {
					attributevalue = engine.NV(t)
				} else {
					ui.Warn().Msgf("Failed to convert attribute %v value %2x to timestamp: %v", attribute.String(), tvalue, err)
				}
			case 12:
				if t, err := time.Parse("060102150405", tvalue); err == nil {
					attributevalue = engine.NV(t)
				} else {
					ui.Warn().Msgf("Failed to convert attribute %v value %2x to timestamp: %v", attribute.String(), tvalue, err)
				}
			default:
				ui.Warn().Msgf("Failed to convert attribute %v value %v to timestamp (unsupported length): %v", attribute.String(), tvalue, len(tvalue))
			}
		case PKIExpirationPeriod, PKIOverlapPeriod:
			nss := binary.BigEndian.Uint64([]byte(value))
			secs := nss / 10000000
			var period string
			if (secs%31536000) == 0 && (secs/31536000) > 1 {
				period = fmt.Sprintf("v% years", secs/31536000)
			} else if (secs%2592000) == 0 && (secs/2592000) > 1 {
				period = fmt.Sprintf("v% months", secs/2592000)
			} else if (secs%604800) == 0 && (secs/604800) > 1 {
				period = fmt.Sprintf("v% weeks", secs/604800)
			} else if (secs%86400) == 0 && (secs/86400) > 1 {
				period = fmt.Sprintf("v% days", secs/86400)
			} else if (secs%3600) == 0 && (secs/3600) > 1 {
				period = fmt.Sprintf("v% hours", secs/3600)
			}
			if period != "" {
				attributevalue = engine.NV(period)
			} else {
				attributevalue = engine.NV(value)
			}
		case AttributeSecurityGUID, SchemaIDGUID, MSDSConsistencyGUID, RightsGUID:
			switch len(value) {
			case 16:
				guid, err := uuid.FromBytes([]byte(value))
				if err == nil {
					guid = util.SwapUUIDEndianess(guid)
					attributevalue = engine.NV(guid)
				} else {
					ui.Warn().Msgf("Failed to convert attribute %v value %2x to GUID: %v", attribute.String(), []byte(value), err)
				}
			case 36:
				guid, err := uuid.FromString(value)
				if err == nil {
					attributevalue = engine.NV(guid)
				} else {
					ui.Warn().Msgf("Failed to convert attribute %v value %2x to GUID: %v", attribute.String(), value, err)
				}
			}
		case ObjectGUID:
			guid, err := uuid.FromBytes([]byte(value))
			if err == nil {
				// 	guid = SwapUUIDEndianess(guid)
				attributevalue = engine.NV(guid)
			} else {
				ui.Warn().Msgf("Failed to convert attribute %v value %2x to GUID: %v", attribute.String(), []byte(value), err)
			}
		case ObjectSid, SIDHistory, SecurityIdentifier, CreatorSID:
			sid, _, _ := windowssecurity.BytesToSID([]byte(value))
			attributevalue = engine.NV(sid)
		case MSDSAllowedToActOnBehalfOfOtherIdentity, FRSRootSecurity, MSDFSLinkSecurityDescriptorv2,
			MSDSGroupMSAMembership, NTSecurityDescriptor, PKIEnrollmentAccess:
			sd, err := engine.CacheOrParseSecurityDescriptor(value)
			if err == nil {
				attributevalue = engine.NV(sd)
			} else {
				ui.Warn().Msgf("Failed to convert attribute %v value %2x to security descriptor: %v", attribute.String(), []byte(value), err)
			}
		default:
			// AUTO CONVERSION - WHAT COULD POSSIBLY GO WRONG
			if value == "true" || value == "TRUE" {
				attributevalue = engine.NV(true)
				break
			} else if value == "false" || value == "FALSE" {
				attributevalue = engine.NV(true)
				break
			}

			if strings.HasSuffix(value, "Z") { // "20171111074031.0Z"
				// Lets try as a timestamp
				tvalue := strings.TrimSuffix(value, "Z")  // strip "Z"
				tvalue = strings.TrimSuffix(tvalue, ".0") // strip ".0"
				if t, err := time.Parse("20060102150405", tvalue); err == nil {
					attributevalue = engine.NV(t)
					break
				}
			}

			// Integer
			if intval, err := strconv.ParseInt(value, 10, 64); err == nil {
				attributevalue = engine.NV(intval)
				break
			}

			// Just a string
			attributevalue = engine.NV(value)
		}

		if attributevalue != nil {
			destination = append(destination, attributevalue)
		} else {
			skipped++
		}
	}

	return destination
}
