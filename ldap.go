package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/schollz/progressbar/v3"
)

type AD struct {
	Domain     string
	Server     string
	Port       uint16
	User       string
	Password   string
	AuthDomain string
	Unsafe     bool
	StartTLS   bool
	IgnoreCert bool

	conn *ldap.Conn
}

func (ad *AD) Connect(authmode byte) error {
	if ad.AuthDomain == "" {
		ad.AuthDomain = ad.Domain
	}
	if ad.Unsafe {
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ad.Server, ad.Port))
		if err != nil {
			return err
		}
		ad.conn = conn
	} else if ad.StartTLS {
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ad.Server, ad.Port))
		if err != nil {
			return err
		}

		err = conn.StartTLS(&tls.Config{ServerName: ad.Server})
		if err != nil {
			return err
		}
		ad.conn = conn
	} else {
		config := &tls.Config{
			ServerName:         ad.Server,
			InsecureSkipVerify: ad.IgnoreCert,
		}
		conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ad.Server, ad.Port), config)
		if err != nil {
			return err
		}
		ad.conn = conn
	}
	var err error
	switch authmode {
	case 0:
		err = ad.conn.UnauthenticatedBind(ad.User)
	case 1:
		err = ad.conn.Bind(ad.User, ad.Password)
	case 2:
		err = ad.conn.MD5Bind(ad.AuthDomain, ad.User, ad.Password)
	case 3:
		err = ad.conn.NTLMBind(ad.AuthDomain, ad.User, ad.Password)
	case 4:
		err = ad.conn.NTLMBindWithHash(ad.AuthDomain, ad.User, ad.Password)
	case 5:
		return ad.gssapiConnect()
	default:
		return fmt.Errorf("Unknown bind method %v", authmode)
	}
	if err != nil {
		return err
	}

	return nil
}

func (ad *AD) Disconnect() error {
	if ad.conn == nil {
		return errors.New("Not connected")
	}
	ad.conn.Close()
	return nil
}

func (ad *AD) RootDn() string {
	return "dc=" + strings.Replace(ad.Domain, ".", ",dc=", -1)
}

func (ad *AD) Dump(searchbase string, query string, attributes []string, nosacl bool, chunkSize int) ([]*RawObject, error) {
	bar := progressbar.NewOptions(-1,
		progressbar.OptionSetDescription("Dumping from "+searchbase+" ..."),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("objects"),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
		progressbar.OptionThrottle(time.Second*1),
	)

	var controls []ldap.Control

	if nosacl {
		sdcontrol := &ControlInteger{
			ControlType:  "1.2.840.113556.1.4.801",
			Criticality:  true,
			ControlValue: int64(7),
		}
		controls = append(controls, sdcontrol)
	}

	if chunkSize > 0 {
		paging := ldap.NewControlPaging(uint32(chunkSize))
		controls = append(controls, paging)
	}

	if query == "" {
		query = "(objectClass=*)"
	}

	var objects []*RawObject

	for {
		request := ldap.NewSearchRequest(
			searchbase, // The base dn to search
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			query,      // The filter to apply
			attributes, // A list attributes to retrieve
			controls,
		)

		response, err := ad.conn.Search(request)
		if err != nil {
			return objects, fmt.Errorf("Failed to execute search request: %w", err)
		}

		// For a page of results, iterate through the reponse and pull the individual entries
		for _, entry := range response.Entries {
			newObject := &RawObject{}
			err = newObject.IngestLDAP(entry)
			if err == nil {
				objects = append(objects, newObject)
				bar.Add(1)
			}
		}

		responseControl := ldap.FindControl(response.Controls, ldap.ControlTypePaging)
		if rctrl, ok := responseControl.(*ldap.ControlPaging); rctrl != nil && ok && len(rctrl.Cookie) != 0 {
			pagingControl := ldap.FindControl(controls, ldap.ControlTypePaging)
			if sctrl, ok := pagingControl.(*ldap.ControlPaging); sctrl != nil && ok {
				sctrl.SetCookie(rctrl.Cookie)
				continue
			}
		}

		break
	}

	bar.Finish()

	return objects, nil
}

type ControlInteger struct {
	ControlType  string
	Criticality  bool
	ControlValue int64
}

// GetControlType returns the OID
func (c *ControlInteger) GetControlType() string {
	return c.ControlType
}

// Encode returns the ber packet representation
func (c *ControlInteger) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.ControlType, "Control Type ("+c.ControlType+")"))
	if c.Criticality {
		packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality, "Criticality"))
	}

	// p2 ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value")
	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value")
	value := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control Value Sequence")
	value.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.ControlValue, "Integer"))
	p2.AppendChild(value)
	packet.AppendChild(p2)

	return packet
}

// String returns a human-readable description
func (c *ControlInteger) String() string {
	return fmt.Sprintf("Control Type: %v  Criticality: %t  Control Value: %v", c.ControlType, c.Criticality, c.ControlValue)
}

func LDAPtoMapStringInterface(e *ldap.Entry) map[string]interface{} {
	result := make(map[string]interface{})
	for _, attribute := range e.Attributes {
		if len(attribute.Values) == 1 {
			result[attribute.Name] = attribute.Values[0]
		} else {
			result[attribute.Name] = attribute.Values
		}
	}
	return result
}
