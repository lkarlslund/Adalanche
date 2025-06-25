//go:build windows
// +build windows

package collect

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	ldap "github.com/lkarlslund/ldap/v3"
	"github.com/lkarlslund/ldap/v3/gssapi"
	"github.com/pierrec/lz4/v4"
	"github.com/pkg/errors"
	"github.com/tinylib/msgp/msgp"
)

func GetSSPIClient() (ldap.GSSAPIClient, error) {
	return gssapi.NewSSPIClient()
}

//go:generate go tool github.com/dmarkham/enumer -type=LDAPAuth -json -output ldap_native_enums_windows.go

type LDAPAuth uint

const (
	LDAP_AUTH_SIMPLE    LDAPAuth = 0x80
	LDAP_AUTH_SASL      LDAPAuth = 0x83
	LDAP_AUTH_OTHERKIND LDAPAuth = 0x86
	LDAP_AUTH_MSN       LDAPAuth = LDAP_AUTH_OTHERKIND | 0x0800
	LDAP_AUTH_NEGOTIATE LDAPAuth = LDAP_AUTH_OTHERKIND | 0x0400
	LDAP_AUTH_NTLM      LDAPAuth = LDAP_AUTH_OTHERKIND | 0x1000
	LDAP_AUTH_DPA       LDAPAuth = LDAP_AUTH_OTHERKIND | 0x2000
	LDAP_AUTH_DIGEST    LDAPAuth = LDAP_AUTH_OTHERKIND | 0x4000
	LDAP_AUTH_SSPI      LDAPAuth = LDAP_AUTH_NEGOTIATE
)

var (
	nativeldap = Command.Flags().Bool("nativeldap", true, "Use native Windows LDAP library rather than multiplatform Golang LDAP library")
	referrals  = Command.Flags().Bool("referrals", false, "Follow referrals (native Windows LDAP only)")
	timeout    = Command.Flags().Duration("timeout", time.Second*30, "timeout for ldap operations (native Windows LDAP only)")
	signing    = Command.Flags().Bool("signing", false, "enable encryption and signing over non-TLS sessions")
)

var ignoreCertCallback = syscall.NewCallback(func(connection uintptr, trustedcas uintptr, ppServerCert uintptr) uintptr {
	return 1
})

func init() {
	findDomain = append(findDomain,
		DomainDetector{
			Name: "last GPO domain",
			Func: func() string {
				// Read string from registry
				value, err := windowssecurity.ReadRegistryKey(`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\MachineDomain`)
				if err == nil {
					return fmt.Sprintf("%v", value)
				} else {
					ui.Warn().Msgf("Error reading last GPO domain from registry: %v", err)
				}
				return ""
			},
		},
	)

	CreateDumper = func(opts LDAPOptions) LDAPDumper {
		if *nativeldap {
			return &WAD{
				LDAPOptions: opts,
			}
		} else {
			return &AD{
				LDAPOptions: opts,
			}
		}
	}

	authmodeflag := Command.Flag("authmode")
	authmodeflag.DefValue = "negotiate"
	authmodeflag.Value.Set("negotiate")
	authmodeflag.Usage = "Bind mode: unauth/anonymous, basic/simple, digest/md5, ntlm, negotiate/sspi - multiplatform only: kerberoscache, ntlmpth (password is hash)"
}

// Windows native LDAP AD dumper
type WAD struct {
	LDAPOptions

	conn WLDAP

	collected int
}

func (a *WAD) Connect() error {
	var chosenserver string
	var err error
	for _, server := range a.Servers {
		err = a.connectToServer(server)
		if err == nil {
			chosenserver = server
			break
		}
		ui.Error().Msgf("Problem connecting to %v: %v - trying next server...", server, err)
	}
	if err != nil {
		return fmt.Errorf("Problem connecting to all servers, giving up")
	}
	ui.Info().Msgf("Connected to %v:%v", chosenserver, a.Port)

	// https://docs.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_bind_s
	var res uintptr
	switch a.AuthMode {
	case Anonymous:
		ui.Info().Msg("Anonymous bind")
		res, _, err = wldap32_ldap_bind_s.Call(
			uintptr(a.conn),
			uintptr(unsafe.Pointer(MakeCString(""))),
			uintptr(unsafe.Pointer(MakeCString(""))),
			uintptr(LDAP_AUTH_SIMPLE),
		)
	case Basic:
		ui.Info().Msg("Simple bind")
		res, _, err = wldap32_ldap_bind_s.Call(
			uintptr(a.conn),
			uintptr(unsafe.Pointer(MakeCString(a.User))),
			uintptr(unsafe.Pointer(MakeCString(a.Password))),
			uintptr(LDAP_AUTH_SIMPLE),
		)
	case Digest, NTLM, Negotiate:
		var ldapauthmode LDAPAuth
		switch a.AuthMode {
		case Digest:
			ldapauthmode = LDAP_AUTH_DIGEST
		case NTLM:
			ldapauthmode = LDAP_AUTH_NTLM
		case Negotiate:
			ldapauthmode = LDAP_AUTH_NEGOTIATE
		}
		if a.User == "" {
			ui.Info().Msgf("Using current user authentication mode %v", ldapauthmode)
			res, _, err = wldap32_ldap_bind_s.Call(
				uintptr(a.conn),
				0,
				0,
				uintptr(ldapauthmode),
			)
		} else {
			ui.Info().Msgf("Using user %v authentication mode %v", a.User, ldapauthmode)
			auth := SEC_WINNT_AUTH_IDENTITY_A{
				User:           MakeWCString(a.User),
				UserLength:     uint32(len(a.User)),
				Domain:         MakeWCString(a.AuthDomain),
				DomainLength:   uint32(len(a.AuthDomain)),
				Password:       MakeWCString(a.Password),
				PasswordLength: uint32(len(a.Password)),
				Flags:          SEC_WINNT_AUTH_IDENTITY_UNICODE,
			}
			res, _, err = wldap32_ldap_bind_s.Call(
				uintptr(a.conn),
				0,
				uintptr(unsafe.Pointer(&auth)),
				uintptr(ldapauthmode),
			)
		}
	default:
		return fmt.Errorf("Unsupported auth mode for native Windows LDAP: %v", a.AuthMode)
	}

	if err != syscall.Errno(0) {
		return err
	}
	if LDAPError(res) != LDAP_SUCCESS {
		return fmt.Errorf("ldap_bind_s failed with %v", LDAPError(res))
	}

	return nil
}

func (a *WAD) connectToServer(server string) error {
	switch a.TLSMode {
	case NoTLS, StartTLS:
		ui.Info().Msgf("Setting up unencrypted LDAP session to %s:%d", server, a.Port)
		ldap, _, err := wldap32_ldap_init.Call(uintptr(unsafe.Pointer(MakeCString(server))), uintptr(a.Port))
		if err != syscall.Errno(0) {
			return err
		}

		a.conn = WLDAP(ldap)
	case TLS:
		ui.Info().Msgf("Setting up TLS encrypted LDAP session to %s:%d", server, a.Port)
		ldap, _, err := wldap32_ldap_sslinit.Call(uintptr(unsafe.Pointer(MakeCString(server))), uintptr(a.Port), uintptr(1))
		if err != syscall.Errno(0) {
			return err
		}

		a.conn = WLDAP(ldap)
	default:
		return errors.New("unknown transport mode")
	}

	timeout_secs := int32(timeout.Seconds())

	a.conn.set_option(LDAP_OPT_PROTOCOL_VERSION, LDAP_VERSION3)

	a.conn.set_option(LDAP_OPT_SIZELIMIT, uintptr(a.SizeLimit))

	if *signing {
		if a.TLSMode != NoTLS {
			return fmt.Errorf("Can't enable signing on anything but unencrypted connections (--tlsmode NoTLS)")
		}
		if a.AuthMode != NTLM && a.AuthMode != Negotiate {
			return fmt.Errorf("Can't enable signing on anything but NTLM or NEGOTIATE sessions (--authmode ntlm or --authmode negotiate)")
		}
		a.conn.set_option(LDAP_OPT_SIGN, 1)
	}

	if *referrals {
		a.conn.set_option(LDAP_OPT_REFERRALS, 1)
	} else {
		a.conn.set_option(LDAP_OPT_REFERRALS, 0)
	}

	if *ignoreCert {
		a.conn.set_option_direct(LDAP_OPT_SERVER_CERTIFICATE, ignoreCertCallback)
	}

	ui.Info().Msgf("Connecting to %s:%d", server, a.Port)
	res, _, _ := wldap32_ldap_connect.Call(uintptr(a.conn), uintptr(unsafe.Pointer(&timeout_secs)))
	if LDAPError(res) != LDAP_SUCCESS {
		a.conn.unbind()
		if LDAPError(res) == LDAP_SERVER_DOWN {
			return fmt.Errorf("ldap_connect failed with %v, connection issue or invalid certificate (try --ignorecert)", LDAPError(res))
		}
		return fmt.Errorf("ldap_connect failed with %v", LDAPError(res))
	}

	if a.TLSMode == StartTLS {
		ui.Info().Msg("Upgrading unencrypted connection to TLS")
		var errorval uint64
		res, _, err := wldap32_ldap_start_tls_s.Call(
			uintptr(a.conn),
			uintptr(unsafe.Pointer(&errorval)),
			0,
			0,
			0,
		)
		if err != syscall.Errno(0) {
			return err
		}
		if LDAPError(res) == LDAP_SERVER_DOWN {
			return fmt.Errorf("ldap_connect failed with %v, connection issue or invalid certificate (try --ignorecert)", LDAPError(res))
		}
		if LDAPError(res) != LDAP_SUCCESS {
			return fmt.Errorf("ldap_start_tls_s failed with %v (code %v)", LDAPError(res), errorval)
		}
	}

	return nil
}

func (a *WAD) Disconnect() error {
	if a.conn == 0 {
		return errors.New("not connected")
	}
	err := a.conn.unbind_s()
	a.conn = 0
	return err
}

func (a *WAD) Dump(do DumpOptions) ([]activedirectory.RawObject, error) {
	timeout_secs := int32(timeout.Seconds())

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

	var objects []activedirectory.RawObject
	var err error

	var scarray []*LDAPControl // 0 = paging, 1 = NoSACL, 2 = nil
	if do.ChunkSize > 0 {
		paging, err := a.conn.CreatePageControl(nil, uint32(do.ChunkSize))
		if err != nil {
			return nil, err
		}
		scarray = append(scarray, paging)
	}

	if do.NoSACL {
		nosaclcontrol := LDAPControl{
			oid:        MakeCString("1.2.840.113556.1.4.801"),
			iscritical: true,
		}

		value := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control Value Sequence")
		value.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 7, "Integer"))
		berdata := value.Bytes()

		nosaclcontrol.ber = LDAPBerval{
			val: &berdata[0],
			len: uint64(len(berdata)),
		}

		scarray = append(scarray, &nosaclcontrol)
	}

	if do.Query == "" {
		do.Query = "(objectClass=*)"
	}

	scarray = append(scarray, nil) // zero terminated array
	ui.Trace().Msgf("Searching for %v at '%v'", do.Query, do.SearchBase)

	for {
		search, err := a.conn.search(do.SearchBase, do.Query, do.Scope, do.Attributes, &scarray[0], int(timeout_secs), do.ChunkSize)
		if err != nil {
			return nil, err
		}

		// Paging loop
		controls, returncode, err := search.parse()
		if err != nil {
			return nil, err
		}
		if LDAPError(returncode) != LDAP_SUCCESS {
			return nil, fmt.Errorf("ldap_search_ext_s returned %v", LDAPError(returncode))
		}

		var entry LDAPMessage
		entry, err = search.first_entry()
		for err == nil {
			var item activedirectory.RawObject
			item.Init()

			dn := entry.get_dn()
			if dn != nil {
				item.DistinguishedName = dn.String()
				mem_free(uintptr(unsafe.Pointer(dn)))
			}

			var ber LDAPBERElement
			attr := entry.first_attribute(&ber)

			if attr == nil {
				ui.Warn().Msgf("No attribute data for %v", item.DistinguishedName)
			}

			for attr != nil {
				attrName := attr.String()

				lvalues := entry.get_values_len(attr)

				var numvalues int
				for i := 0; i < len(lvalues); i++ {
					if lvalues[i] == nil {
						numvalues = i
						break
					}
				}

				if numvalues == 0 && attrName != "member" {
					ui.Warn().Msgf("Object %v attribute %v has no values", item.DistinguishedName, attrName)
				}

				values := make([]string, numvalues)
				for i := 0; i < numvalues; i++ {
					if do.ReturnObjects {
						// Dedup if we're returning objects
						values[i] = string(lvalues[i].Data())
					} else {
						// Don't bother deduping if we're not returning objects
						values[i] = string(lvalues[i].Data())
					}
				}

				lvalues.free()

				mem_free(uintptr(unsafe.Pointer(attr)))

				item.Attributes[attrName] = values

				attr = entry.next_attribute(ber)
			}

			if e != nil {
				err = item.EncodeMsg(e)
				if err != nil {
					return nil, fmt.Errorf("problem encoding LDAP object %v: %v", item.DistinguishedName, err)
				}
			}

			if do.OnObject != nil {
				do.OnObject(&item)
			}

			if do.ReturnObjects {
				// Grow one page at a time
				if len(objects) == cap(objects) {
					newobjects := make([]activedirectory.RawObject, len(objects), cap(objects)+do.ChunkSize)
					copy(newobjects, objects)
					objects = newobjects
				}
				objects = append(objects, item)
			}

			a.collected++
			bar.Add(1)

			entry = entry.next_entry()
			if uintptr(entry.msg) == 0 {
				break
			}
		}
		search.free()

		if do.ChunkSize > 0 {
			cookie, _, err := a.conn.ParsePageControl(controls)
			if err != nil {
				ui.Debug().Msgf("Error parsing page controls: %v", err)
			}

			if cookie == nil || cookie.len == 0 {
				ui.Trace().Msgf("No more results")
				break
			}

			ui.Trace().Msgf("Continuing search with cookie %0X", cookie.Data())

			paging, err := a.conn.CreatePageControl(cookie, uint32(do.ChunkSize))
			if err != nil {
				return nil, err
			}

			// Free the old pagingcontrol that was created by DLL
			oldcontrol := scarray[0]
			scarray[0] = paging
			oldcontrol.free()
		} else {
			// No paging requested
			break
		}
	}

	runtime.KeepAlive(scarray)

	bar.Finish()
	if e != nil {
		e.Flush()
	}

	return objects, err
}

func (w *WAD) Len() int {
	items := w.collected
	w.collected = 0
	return items
}

var (
	wldap32                      = syscall.NewLazyDLL("Wldap32.dll")
	wldap32_ldap_bind_s          = wldap32.NewProc("ldap_bind_s")
	wldap32_ldap_connect         = wldap32.NewProc("ldap_connect")
	wldap32_ldap_count_entries   = wldap32.NewProc("ldap_count_entries")
	wldap32_ldap_count_values    = wldap32.NewProc("ldap_count_values")
	wldap32_ldap_get_dn          = wldap32.NewProc("ldap_get_dn")
	wldap32_ldap_get_option      = wldap32.NewProc("ldap_get_option")
	wldap32_ldap_get_values      = wldap32.NewProc("ldap_get_values")
	wldap32_ldap_get_values_len  = wldap32.NewProc("ldap_get_values_len")
	wldap32_ldap_first_entry     = wldap32.NewProc("ldap_first_entry")
	wldap32_ldap_first_attribute = wldap32.NewProc("ldap_first_attribute")
	wldap32_ldap_init            = wldap32.NewProc("ldap_init")
	wldap32_ldap_sslinit         = wldap32.NewProc("ldap_sslinit")
	wldap32_ldap_start_tls_s     = wldap32.NewProc("ldap_start_tls_sA")
	wldap32_ldap_memfree         = wldap32.NewProc("ldap_memfree")
	wldap32_ldap_msgfree         = wldap32.NewProc("ldap_msgfree")
	wldap32_ldap_next_entry      = wldap32.NewProc("ldap_next_entry")
	wldap32_ldap_next_attribute  = wldap32.NewProc("ldap_next_attribute")
	wldap32_ldap_search_ext_s    = wldap32.NewProc("ldap_search_ext_s")
	wldap32_ldap_set_option      = wldap32.NewProc("ldap_set_option")
	wldap32_ldap_unbind          = wldap32.NewProc("ldap_unbind")
	wldap32_ldap_unbind_s        = wldap32.NewProc("ldap_unbind_s")
	wldap32_ldap_value_free      = wldap32.NewProc("ldap_value_free")
	wldap32_ldap_value_free_len  = wldap32.NewProc("ldap_value_free_len")

	wldap32_ldap_parse_result        = wldap32.NewProc("ldap_parse_result")
	wldap32_ldap_create_page_control = wldap32.NewProc("ldap_create_page_control")
	wldap32_ldap_parse_page_control  = wldap32.NewProc("ldap_parse_page_control")
	wldap32_ldap_control_free        = wldap32.NewProc("ldap_control_free")

	// wldap32_ber_alloc_t = wldap32.NewProc("ber_alloc_t")
	// wldap32_ber_flatten = wldap32.NewProc("ber_flatten")
	// wldap32_ber_bvfree  = wldap32.NewProc("ber_bvfree")
	wldap32_ber_free = wldap32.NewProc("ber_free")
)

const (
	SEC_WINNT_AUTH_IDENTITY_ANSI    = 0x1
	SEC_WINNT_AUTH_IDENTITY_UNICODE = 0x2
)

type WLDAP syscall.Handle

type LDAPValues [16384]LDAPValue

type LDAPValue uintptr

type LDAPMessage struct {
	msg  uintptr
	ldap WLDAP
}

func (ldm LDAPMessage) get_dn() *CString {
	res, _, err := wldap32_ldap_get_dn.Call(uintptr(ldm.ldap), ldm.msg)
	if err != syscall.Errno(0) {
		return nil
	}
	return (*CString)(unsafe.Pointer(res))
}

func (ber LDAPBERElement) free() {
	wldap32_ber_free.Call(uintptr(ber), uintptr(0))
}

func mem_free(ptr uintptr) error {
	res, _, err := wldap32_ldap_memfree.Call(ptr)
	if err != syscall.Errno(0) {
		return err
	}
	if LDAPError(res) != LDAP_SUCCESS {
		return fmt.Errorf("ldap_memfree failed: %v", LDAPError(res))
	}
	return nil
}

func (value LDAPValue) free() error {
	res, res2, err := wldap32_ldap_value_free.Call(uintptr(unsafe.Pointer(value)))

	if LDAPError(res) != LDAP_SUCCESS {
		return fmt.Errorf("ldap_value_free failed with %s %v %v", LDAPError(res), res2, err)
	}
	return nil
}

func (value *LDAPBerval) Get() []byte {
	if value.val == nil {
		return nil
	}
	return GoBytes(value.val, int(value.len))
}

func (value *LDAPBervalues) free() error {
	res, res2, err := wldap32_ldap_value_free_len.Call(uintptr(unsafe.Pointer(value)))
	if err != syscall.Errno(0) {
		return err
	}
	if LDAPError(res) != LDAP_SUCCESS {
		return fmt.Errorf("ldap_value_free_len failed with %s %v %v", LDAPError(res), res2, err)
	}
	return nil
}

func (msg LDAPMessage) free() error {
	res, res2, err := wldap32_ldap_msgfree.Call(uintptr(msg.msg))
	if err != syscall.Errno(0) {
		return err
	}
	if LDAPError(res) != LDAP_SUCCESS {
		return fmt.Errorf("ldap_msgfree failed with %s %v %v", LDAPError(res), res2, err)
	}
	return nil
}

func (ldap WLDAP) set_option(option LDAPOption, value uintptr) error {
	res, res2, err := wldap32_ldap_set_option.Call(uintptr(ldap), uintptr(option), uintptr(unsafe.Pointer(&value)))
	if err != syscall.Errno(0) {
		return err
	}
	if LDAPError(res) != LDAP_SUCCESS {
		return fmt.Errorf("ldap_value_free_len failed with %s %v %v", LDAPError(res), res2, err)
	}
	return nil
}

func (ldap WLDAP) set_option_direct(option LDAPOption, value uintptr) error {
	res, res2, err := wldap32_ldap_set_option.Call(uintptr(ldap), uintptr(option), value)
	if err != syscall.Errno(0) {
		return err
	}
	if LDAPError(res) != LDAP_SUCCESS {
		return fmt.Errorf("ldap_value_free_len failed with %s %v %v", LDAPError(res), res2, err)
	}
	return nil
}

func (ldap WLDAP) get_option(option LDAPOption) (int32, error) {
	var result int32
	res, res2, err := wldap32_ldap_get_option.Call(uintptr(ldap), uintptr(option), uintptr(unsafe.Pointer(&result)))
	if err != syscall.Errno(0) {
		return result, err
	}
	if LDAPError(res) != LDAP_SUCCESS {
		return result, fmt.Errorf("ldap_get_option failed with %s %v %v", LDAPError(res), res2, err)
	}
	return result, nil
}

func (msg LDAPMessage) count_entries() (int, error) {
	res, _, err := wldap32_ldap_count_entries.Call(uintptr(msg.ldap), uintptr(unsafe.Pointer(msg.msg)))
	if err != syscall.Errno(0) {
		return 0, err
	}
	return int(res), nil
}

func (msg LDAPMessage) first_entry() (LDAPMessage, error) {
	res, _, err := wldap32_ldap_first_entry.Call(uintptr(msg.ldap), uintptr(unsafe.Pointer(msg.msg)))
	if err != syscall.Errno(0) {
		return LDAPMessage{}, err
	}
	return LDAPMessage{
		msg:  res,
		ldap: msg.ldap,
	}, nil
}

type LDAPBervalues [16384]*LDAPBerval

func (msg LDAPMessage) get_values_len(key *CString) *LDAPBervalues {
	res, _, _ := wldap32_ldap_get_values_len.Call(uintptr(msg.ldap), uintptr(unsafe.Pointer(msg.msg)), uintptr(unsafe.Pointer(key)))
	return (*LDAPBervalues)(unsafe.Pointer(res))
}

type LDAPBERElement uintptr

func (msg LDAPMessage) parse() (**LDAPControl, uint32, error) {
	var servercontrols **LDAPControl
	var returncode uint32
	res, _, err := wldap32_ldap_parse_result.Call(
		uintptr(msg.ldap),
		uintptr(unsafe.Pointer(msg.msg)),
		uintptr(unsafe.Pointer(&returncode)),     // ReturnCode
		0,                                        // MatchedDNs
		0,                                        // Errormessage
		0,                                        // Referrals
		uintptr(unsafe.Pointer(&servercontrols)), // Servercontrols
		0,                                        // Freeit
	)
	if err != syscall.Errno(0) {
		return nil, 0, err
	}
	if LDAPError(res) != LDAP_SUCCESS {
		return nil, 0, fmt.Errorf("ldap_parse_result failed with %s", LDAPError(res))
	}
	return servercontrols, returncode, nil
}

func (msg LDAPMessage) first_attribute(ber *LDAPBERElement) *CString {
	ptr, _, _ := wldap32_ldap_first_attribute.Call(uintptr(msg.ldap), uintptr(unsafe.Pointer(msg.msg)), uintptr(unsafe.Pointer(ber)))
	return (*CString)(unsafe.Pointer(ptr))
}

func (msg LDAPMessage) next_attribute(ber LDAPBERElement) *CString {
	ptr, _, _ := wldap32_ldap_next_attribute.Call(uintptr(msg.ldap), uintptr(unsafe.Pointer(msg.msg)), uintptr(unsafe.Pointer(ber)))
	return (*CString)(unsafe.Pointer(ptr))
}

func (msg LDAPMessage) next_entry() LDAPMessage {
	res, _, _ := wldap32_ldap_next_entry.Call(uintptr(msg.ldap), uintptr(unsafe.Pointer(msg.msg)))
	return LDAPMessage{
		msg:  res,
		ldap: msg.ldap,
	}
}

func (val *LDAPValues) count_values() (int, error) {
	res, _, err := wldap32_ldap_count_values.Call(uintptr(unsafe.Pointer(val)))
	return int(res), err
}

func (ldap WLDAP) bind_s(username string, password string) error {
	var res uintptr
	var err error

	if username != "" && password != "" {
		// username should be in format "name@domain" not in DN or simple user name format
		res, _, err = wldap32_ldap_bind_s.Call(uintptr(ldap), uintptr(unsafe.Pointer(MakeCString(username))), uintptr(unsafe.Pointer(MakeCString(password))), uintptr(LDAP_AUTH_SIMPLE))
	} else {
		res, _, err = wldap32_ldap_bind_s.Call(uintptr(ldap), uintptr(unsafe.Pointer(nil)), uintptr(unsafe.Pointer(nil)), uintptr(LDAP_AUTH_NEGOTIATE))
	}

	if err != syscall.Errno(0) {
		return err
	}

	if LDAPError(res) != LDAP_SUCCESS {
		return fmt.Errorf("ldap_bind_s failed with %s", LDAPError(res))
	}

	return nil
}

func (ldap WLDAP) search(base string, filter string, scope int, attributes []string, servercontrols **LDAPControl, timeout, chunksize int) (LDAPMessage, error) {
	cbase := MakeCString(base)
	cfilter := MakeCString(filter)
	msg := LDAPMessage{ldap: ldap}

	l_timeval := struct {
		tv_sec  int32
		tv_usec int32
	}{
		int32(timeout),
		0,
	}

	res, _, err := wldap32_ldap_search_ext_s.Call(
		uintptr(ldap),
		uintptr(unsafe.Pointer(cbase)),
		uintptr(scope),
		uintptr(unsafe.Pointer(cfilter)),
		0,                                       // Attributes to fetch
		0,                                       // Get both attributes and values
		uintptr(unsafe.Pointer(servercontrols)), // ServerControls
		0,                                       // ClientControls
		uintptr(unsafe.Pointer(&l_timeval)),     // Timeout
		uintptr(chunksize),                      // Results per page
		uintptr(unsafe.Pointer(&msg.msg)),
	)
	runtime.KeepAlive(cbase)
	runtime.KeepAlive(cfilter)
	runtime.KeepAlive(servercontrols)
	runtime.KeepAlive(l_timeval)

	if err != syscall.Errno(0) {
		return msg, err
	}

	if LDAPError(res) != LDAP_SUCCESS {
		return msg, fmt.Errorf("ldap_search_s failed with %s", LDAPError(res))
	}

	return msg, nil
}

type LDAPBerval struct {
	len uint64
	val *uint8
}

func (lbv LDAPBerval) Data() []byte {
	return GoBytes(lbv.val, int(lbv.len))
}

func (lbv LDAPBerval) String() string {
	return fmt.Sprintf("%0 X", lbv.Data())
}

func (ldap WLDAP) unbind() error {
	res, res2, err := wldap32_ldap_unbind.Call(uintptr(ldap))
	if err != syscall.Errno(0) {
		return err
	}
	if LDAPError(res) != LDAP_SUCCESS {
		return fmt.Errorf("ldap_unbind failed with %s %v %v", LDAPError(res), res2, err)
	}
	return nil
}

func (ldap WLDAP) unbind_s() error {
	res, res2, err := wldap32_ldap_unbind_s.Call(uintptr(ldap))
	if err != syscall.Errno(0) {
		return err
	}
	if LDAPError(res) != LDAP_SUCCESS {
		return fmt.Errorf("ldap_unbind_s failed with %s %v %v", LDAPError(res), res2, err)
	}
	return nil
}

type LDAPControls [16384]*LDAPControl

type LDAPControl struct {
	oid        *CString
	ber        LDAPBerval
	iscritical bool
}

// Only call this for controls that are returned from the DLL
func (lc *LDAPControl) free() error {
	res, _, err := wldap32_ldap_control_free.Call(uintptr(unsafe.Pointer(lc)))
	if err != syscall.Errno(0) {
		return err
	}
	if LDAPError(res) != LDAP_SUCCESS {
		return fmt.Errorf("ldap_control_free failed with %s", LDAPError(res))
	}
	return nil
}

func (ldap WLDAP) CreatePageControl(cookie *LDAPBerval, pagesize uint32) (*LDAPControl, error) {
	var control *LDAPControl
	iscritical := byte(1)
	res, _, err := wldap32_ldap_create_page_control.Call(
		uintptr(ldap),
		uintptr(pagesize),
		uintptr(unsafe.Pointer(cookie)),
		uintptr(iscritical),
		uintptr(unsafe.Pointer(&control)),
	)
	if err != syscall.Errno(0) {
		return nil, err
	}
	if LDAPError(res) != LDAP_SUCCESS {
		return nil, fmt.Errorf("ldap_create_page_control failed with %s", LDAPError(res))
	}
	return control, nil
}

func (ldap WLDAP) ParsePageControl(lc **LDAPControl) (*LDAPBerval, uint32, error) {
	var cookie *LDAPBerval
	var totalcount uint32
	res, _, err := wldap32_ldap_parse_page_control.Call(
		uintptr(unsafe.Pointer(ldap)),
		uintptr(unsafe.Pointer(lc)),
		uintptr(unsafe.Pointer(&totalcount)),
		uintptr(unsafe.Pointer(&cookie)),
	)
	if err != syscall.Errno(0) {
		return nil, 0, err
	}
	if LDAPError(res) != LDAP_SUCCESS {
		return nil, 0, fmt.Errorf("ldap_parse_page_control failed with %s", LDAPError(res))
	}
	return cookie, totalcount, nil
}

func GoBytes(ptr *uint8, length int) []byte {
	result := make([]byte, length)
	unsafeSlice := unsafe.Slice(ptr, length)
	copy(result, unsafeSlice)
	return result
}

func GoString(ptr *uint8) string {
	if ptr == nil {
		return ""
	}

	res := (*[1000000]byte)(unsafe.Pointer(ptr))
	length := bytes.IndexByte(res[:], 0)
	if length < 1 {
		panic("zero terminated string is not zero terminated")
	}
	return string(res[:length])
}

func MakeCString(input string) *CString {
	chars := append([]byte(input), 0) // null terminated
	return (*CString)(&chars[0])
}

func MakeWCString(input string) *WCString {
	output := utf16.Encode([]rune(input + "\x00"))
	return (*WCString)(&output[0])
}

type WCString uint16

type CString uint8

func (ptr *WCString) String() string {
	data := (*[16384]uint16)(unsafe.Pointer(ptr))
	length := 0
	for i := 0; i < 16384; i++ {
		if data[i] == 0 {
			length = i
			break
		}
		i++
	}
	return string(utf16.Decode(data[:length]))
}

func (ptr *CString) String() string {
	data := (*[16384]uint8)(unsafe.Pointer(ptr))
	length := bytes.IndexByte(data[:], 0)
	if length < 1 {
		return ""
	}
	return string(data[:length])
}

type SEC_WINNT_AUTH_IDENTITY_A struct {
	User           *WCString
	UserLength     uint32
	Domain         *WCString
	DomainLength   uint32
	Password       *WCString
	PasswordLength uint32
	Flags          uint32
}
