package collect

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	ldap "github.com/lkarlslund/ldap/v3"
	"github.com/pierrec/lz4/v4"
	"github.com/schollz/progressbar/v3"
	"github.com/tinylib/msgp/msgp"
)

//go:generate enumer -type=TLSmode -json

type TLSmode byte

const (
	TLS TLSmode = iota
	StartTLS
	NoTLS
)

type AD struct {
	Domain     string
	Server     string
	Port       uint16
	User       string
	Password   string
	AuthDomain string
	TLSMode    TLSmode
	IgnoreCert bool

	conn *ldap.Conn
}

func (ad *AD) Connect(authmode byte) error {
	if ad.AuthDomain == "" {
		ad.AuthDomain = ad.Domain
	}
	switch ad.TLSMode {
	case NoTLS:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ad.Server, ad.Port))
		if err != nil {
			return err
		}
		ad.conn = conn
	case StartTLS:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ad.Server, ad.Port))
		if err != nil {
			return err
		}

		err = conn.StartTLS(&tls.Config{ServerName: ad.Server})
		if err != nil {
			return err
		}
		ad.conn = conn
	case TLS:
		config := &tls.Config{
			ServerName:         ad.Server,
			InsecureSkipVerify: ad.IgnoreCert,
		}
		conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ad.Server, ad.Port), config)
		if err != nil {
			return err
		}
		ad.conn = conn
	default:
		return errors.New("unknown transport mode")
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
		err = ad.conn.NTLMSSPIBind()
	default:
		return fmt.Errorf("unknown bind method %v", authmode)
	}
	if err != nil {
		return err
	}

	return nil
}

func (ad *AD) Disconnect() error {
	if ad.conn == nil {
		return errors.New("not connected")
	}
	ad.conn.Close()
	return nil
}

type DumpOptions struct {
	SearchBase string
	Scope      int
	Query      string
	Attributes []string
	NoSACL     bool
	ChunkSize  int

	OnObject      func(ro *activedirectory.RawObject) error
	WriteToFile   string
	ReturnObjects bool
}

func (ad *AD) RootDn() string {
	return "dc=" + strings.Replace(ad.Domain, ".", ",dc=", -1)
}

func (ad *AD) Dump(da DumpOptions) ([]*activedirectory.RawObject, error) {
	var e *msgp.Writer
	if da.WriteToFile != "" {
		outfile, err := os.Create(da.WriteToFile)
		if err != nil {
			return nil, fmt.Errorf("problem opening domain cache file: %v", err)
		}
		defer outfile.Close()

		boutfile := lz4.NewWriter(outfile)
		lz4options := []lz4.Option{
			lz4.BlockChecksumOption(true),
			// lz4.BlockSizeOption(lz4.BlockSize(51 * 1024)),
			lz4.ChecksumOption(true),
			lz4.CompressionLevelOption(lz4.Level9),
			lz4.ConcurrencyOption(-1),
		}
		boutfile.Apply(lz4options...)
		defer boutfile.Close()
		e = msgp.NewWriter(boutfile)
	}

	bar := progressbar.NewOptions(-1,
		progressbar.OptionSetDescription("Dumping from "+da.SearchBase+" ..."),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("objects"),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
		progressbar.OptionThrottle(time.Second*1),
	)

	var controls []ldap.Control

	if da.NoSACL {
		sdcontrol := &ControlInteger{
			ControlType:  "1.2.840.113556.1.4.801",
			Criticality:  true,
			ControlValue: int64(7),
		}
		controls = append(controls, sdcontrol)
	}

	if da.ChunkSize > 0 {
		paging := ldap.NewControlPaging(uint32(da.ChunkSize))
		controls = append(controls, paging)
	}

	if da.Query == "" {
		da.Query = "(objectClass=*)"
	}

	var objects []*activedirectory.RawObject

	for {
		request := ldap.NewSearchRequest(
			da.SearchBase, // The base dn to search
			da.Scope, ldap.NeverDerefAliases, 0, 0, false,
			da.Query,      // The filter to apply
			da.Attributes, // A list attributes to retrieve
			controls,
		)

		response, err := ad.conn.Search(request)
		if err != nil {
			return objects, fmt.Errorf("failed to execute search request: %w", err)
		}

		// For a page of results, iterate through the reponse and pull the individual entries
		for _, entry := range response.Entries {
			newObject := &activedirectory.RawObject{}
			err = newObject.IngestLDAP(entry)
			if err == nil {
				if e != nil {
					err = newObject.EncodeMsg(e)
					if err != nil {
						return nil, fmt.Errorf("problem encoding LDAP object %v: %v", newObject.DistinguishedName, err)
					}
				}
				if da.OnObject != nil {
					err = da.OnObject(newObject)
					if err != nil {
						return nil, err
					}
				}
				if da.ReturnObjects {
					objects = append(objects, newObject)
				}
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
	if e != nil {
		e.Flush()
	}

	return objects, nil
}

type ControlInteger struct {
	ControlType  string
	Criticality  bool
	ControlValue int64
}

// GetControlType rturns the OID
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
	return fmt.Sprintf("Control Type: %v  Critiality: %t  Control Value: %v", c.ControlType, c.Criticality, c.ControlValue)
}

func LDAPtoMaptringInterface(e *ldap.Entry) map[string]interface{} {
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
