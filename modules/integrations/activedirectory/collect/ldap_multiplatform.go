package collect

import (
	"crypto/tls"
	"errors"
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
	cb "github.com/golang-auth/go-channelbinding"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	ldap "github.com/lkarlslund/ldap/v3"
	"github.com/pierrec/lz4/v4"
	"github.com/tinylib/msgp/msgp"
	"os"
	osuser "os/user"
	"strings"
)

type AD struct {
	conn   *ldap.Conn
	cbData []byte
	LDAPOptions
	items int
}

func (ad *AD) Connect() error {
	var cbData []byte
	_ = cbData // for later
	var chosenserver string
	var err error
	for _, server := range ad.Servers {
		err = ad.connectToServer(server)
		if err == nil {
			chosenserver = server
			break
		}
	}
	if err != nil {
		return fmt.Errorf("Problem connecting to any server: %v", err)
	}
	ad.conn.Debug.Enable(ad.Debug)
	var gerr error
	switch ad.AuthMode {
	case Anonymous:
		ui.Debug().Msgf("Doing unauthenticated bind with user %s", ad.User)
		gerr = ad.conn.UnauthenticatedBind(ad.User)
	case Basic:
		if ad.Password == "" {
			ui.Debug().Msgf("Doing simple unauthenticated bind with user %s", ad.User)
			gerr = ad.conn.UnauthenticatedBind(ad.User)
		} else {
			ui.Debug().Msgf("Doing simple bind with user %s", ad.User)
			gerr = ad.conn.Bind(ad.User, ad.Password)
		}
	case Digest:
		ui.Debug().Msgf("Doing DIGEST-MD5 auth with user %s from domain %s", ad.User, ad.AuthDomain)
		gerr = ad.conn.MD5Bind(ad.AuthDomain, ad.User, ad.Password)
	case KerberosCache:
		upperDomain := strings.ToUpper(ad.Domain)
		kerberosConfig, err := config.NewFromString(fmt.Sprintf(`[libdefaults]
default_realm = %s
default_tgs_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac aes128-cts-hmac-sha1-96 rc4-hmac des-cbc-crc des-cbc-md5
default_tkt_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac aes128-cts-hmac-sha1-96 rc4-hmac des-cbc-crc des-cbc-md5
permitted_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac aes128-cts-hmac-sha1-96 rc4-hmac des-cbc-crc des-cbc-md5
allow_weak_crypto = true
[realms]
%s = {
kdc = %s:88
default_domain = %s
}`,
			upperDomain, upperDomain, chosenserver, upperDomain))
		if err != nil {
			return err
		}
		cachefile := os.Getenv("KRB5CCNAME")
		if cachefile == "" {
			usr, _ := osuser.Current()
			cachefile = "/tmp/krb5cc_" + usr.Uid
		}
		ccache, err := credentials.LoadCCache(cachefile)
		if err != nil {
			return err
		}
		client, err := client.NewFromCCache(ccache, kerberosConfig)
		if err != nil {
			return err
		}
		spn := "ldap/" + chosenserver
		// gc := &gssapi.Client{
		// 	Client: client,
		// }
		gc := &GSSAPIState{
			cfg:    kerberosConfig,
			client: client,
		}
		gerr = ad.conn.GSSAPIBind(gc, spn, "")
	case NTLM:
		if ad.User == "" {
			ui.Debug().Msgf("Doing integrated NTLM auth")
			// Create a GSSAPI client
			sspiClient, err := GetSSPIClient()
			if err != nil {
				return err
			}
			// Bind using supplied GSSAPIClient implementation
			err = ad.conn.GSSAPIBind(sspiClient, "ldap/"+chosenserver, "")
			if err != nil {
				return err
			}
		} else {
			ui.Debug().Msgf("Doing NTLM auth with user %s from domain %s", ad.User, ad.AuthDomain)
			gerr = ad.conn.NTLMBind(ad.AuthDomain, ad.User, ad.Password)
		}
	case NTLMPTH:
		ui.Debug().Msgf("Doing NTLM hash auth with user %s from domain %s", ad.User, ad.AuthDomain)
		gerr = ad.conn.NTLMBindWithHash(ad.AuthDomain, ad.User, ad.Password)
	default:
		return fmt.Errorf("unknown bind method %v", authmode)
	}
	return gerr
}
func (ad *AD) connectToServer(server string) error {
	switch ad.TLSMode {
	case NoTLS:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", server, ad.Port))
		if err != nil {
			return err
		}
		ad.conn = conn
	case StartTLS:
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", server, ad.Port))
		if err != nil {
			return err
		}
		err = conn.StartTLS(&tls.Config{
			ServerName:         server,
			InsecureSkipVerify: ad.IgnoreCert,
		})
		if err != nil {
			return err
		}
		ad.conn = conn
	case TLS:
		config := &tls.Config{
			ServerName:         server,
			InsecureSkipVerify: ad.IgnoreCert,
			MaxVersion:         tls.VersionTLS12,
		}
		conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", server, ad.Port), config)
		if err != nil {
			return err
		}
		if ad.Channelbinding {
			tlsState := conn.ConnectionState()
			if len(tlsState.PeerCertificates) == 0 {
				return errors.New("no peer certificates for channel binding")
			}
			ad.cbData, err = cb.MakeTLSChannelBinding(tlsState, tlsState.PeerCertificates[0], cb.TLSChannelBindingEndpoint)
			if err != nil {
				return err
			}
		}
		ad.conn = ldap.NewConn(conn, true)
		ad.conn.Start()
	default:
		return errors.New("unknown transport mode")
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
func (ad *AD) RootDn() string {
	return "dc=" + strings.Replace(ad.Domain, ".", ",dc=", -1)
}
func (ad *AD) Dump(do DumpOptions) ([]activedirectory.RawObject, error) {
	ad.items = 0
	var e *msgp.Writer
	if do.WriteToFile != "" {
		outfile, err := os.Create(do.WriteToFile)
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
	bar := ui.ProgressBar("Dumping from "+do.SearchBase+" ...", -1)
	defer bar.Finish()
	var controls []ldap.Control
	if do.NoSACL {
		sdcontrol := &ControlInteger{
			ControlType:  "1.2.840.113556.1.4.801",
			Criticality:  true,
			ControlValue: int64(7),
		}
		controls = append(controls, sdcontrol)
	}
	if do.ChunkSize > 0 {
		paging := ldap.NewControlPaging(uint32(do.ChunkSize))
		controls = append(controls, paging)
	}
	if do.Query == "" {
		do.Query = "(objectClass=*)"
	}
	var objects []activedirectory.RawObject
	for {
		request := ldap.NewSearchRequest(
			do.SearchBase, // The base dn to search
			do.Scope, ldap.NeverDerefAliases, 0, 0, false,
			do.Query,      // The filter to apply
			do.Attributes, // A list attributes to retrieve
			controls,
		)
		response, err := ad.conn.Search(request)
		if err != nil {
			return objects, fmt.Errorf("failed to execute search request: %w", err)
		}
		ui.Debug().Msgf("YOU ARE HERE")
		// For a page of results, iterate through the reponse and pull the individual entries
		for _, entry := range response.Entries {
			ad.items++
			newObject := activedirectory.RawObject{}
			err = newObject.IngestLDAP(entry)
			if err == nil {
				if e != nil {
					err = newObject.EncodeMsg(e)
					if err != nil {
						return nil, fmt.Errorf("problem encoding LDAP object %v: %v", newObject.DistinguishedName, err)
					}
				}
				if do.OnObject != nil {
					err = do.OnObject(&newObject)
					if err != nil {
						return nil, err
					}
				}
				if do.ReturnObjects {
					// Grow one page at a time
					if len(objects) == cap(objects) {
						newobjects := make([]activedirectory.RawObject, len(objects), cap(objects)+do.ChunkSize)
						copy(newobjects, objects)
						objects = newobjects
					}
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
func (ad *AD) Len() int {
	return ad.items
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
func LDAPtoMaptringInterface(e *ldap.Entry) map[string]any {
	result := make(map[string]any)
	for _, attribute := range e.Attributes {
		if len(attribute.Values) == 1 {
			result[attribute.Name] = attribute.Values[0]
		} else {
			result[attribute.Name] = attribute.Values
		}
	}
	return result
}
