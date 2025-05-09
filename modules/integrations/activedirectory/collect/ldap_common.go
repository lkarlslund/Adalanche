package collect

import (
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/Showmax/go-fqdn"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/pkg/errors"
)

//go:generate go tool github.com/dmarkham/enumer -type=TLSmode,AuthMode,LDAPScope,LDAPError,LDAPOption -json -output ldap_enums.go
type AuthMode byte

const (
	Anonymous AuthMode = iota
	Basic
	Digest
	KerberosCache
	NTLM
	NTLMPTH
	Negotiate
	MD5    = Digest
	Unauth = Anonymous
	Simple = Basic
)

type TLSmode byte

const (
	TLS TLSmode = iota
	StartTLS
	NoTLS
)

type LDAPScope uint

const (
	LDAP_SCOPE_BASE     LDAPScope = 0x0
	LDAP_SCOPE_ONELEVEL LDAPScope = 0x1
	LDAP_SCOPE_SUBTREE  LDAPScope = 0x2
)

type LDAPError uint

const (
	LDAP_SUCCESS                        LDAPError = 0x00
	LDAP_SIZELIMIT_EXCEEDED             LDAPError = 0x04
	LDAP_ADMIN_LIMIT_EXCEEDED           LDAPError = 0x0b
	LDAP_AFFECTS_MULTIPLE_DSAS          LDAPError = 0x47
	LDAP_ALIAS_DEREF_PROBLEM            LDAPError = 0x24
	LDAP_ALIAS_PROBLEM                  LDAPError = 0x21
	LDAP_ALREADY_EXISTS                 LDAPError = 0x44
	LDAP_ATTRIBUTE_OR_VALUE_EXISTS      LDAPError = 0x14
	LDAP_AUTH_METHOD_NOT_SUPPORTED      LDAPError = 0x07
	LDAP_AUTH_UNKNOWN                   LDAPError = 0x56
	LDAP_BUSY                           LDAPError = 0x33
	LDAP_CLIENT_LOOP                    LDAPError = 0x60
	LDAP_COMPARE_FALSE                  LDAPError = 0x05
	LDAP_COMPARE_TRUE                   LDAPError = 0x06
	LDAP_CONFIDENTIALITY_REQUIRED       LDAPError = 0x0d
	LDAP_CONNECT_ERROR                  LDAPError = 0x5b
	LDAP_CONSTRAINT_VIOLATION           LDAPError = 0x13
	LDAP_CONTROL_NOT_FOUND              LDAPError = 0x5d
	LDAP_DECODING_ERROR                 LDAPError = 0x54
	LDAP_ENCODING_ERROR                 LDAPError = 0x53
	LDAP_FILTER_ERROR                   LDAPError = 0x57
	LDAP_INAPPROPRIATE_AUTH             LDAPError = 0x30
	LDAP_INAPPROPRIATE_MATCHING         LDAPError = 0x12
	LDAP_INSUFFICIENT_RIGHTS            LDAPError = 0x32
	LDAP_INVALID_CREDENTIALS            LDAPError = 0x31
	LDAP_INVALID_DN_SYNTAX              LDAPError = 0x22
	LDAP_INVALID_SYNTAX                 LDAPError = 0x15
	LDAP_IS_LEAF                        LDAPError = 0x23
	LDAP_LOCAL_ERROR                    LDAPError = 0x52
	LDAP_LOOP_DETECT                    LDAPError = 0x36
	LDAP_MORE_RESULTS_TO_RETURN         LDAPError = 0x5f
	LDAP_NAMING_VIOLATION               LDAPError = 0x40
	LDAP_NO_MEMORY                      LDAPError = 0x5a
	LDAP_NO_OBJECT_CLASS_MODS           LDAPError = 0x45
	LDAP_NO_RESULTS_RETURNED            LDAPError = 0x5e
	LDAP_NO_SUCH_ATTRIBUTE              LDAPError = 0x10
	LDAP_NO_SUCH_OBJECT                 LDAPError = 0x20
	LDAP_NOT_ALLOWED_ON_NONLEAF         LDAPError = 0x42
	LDAP_NOT_ALLOWED_ON_RDN             LDAPError = 0x43
	LDAP_NOT_SUPPORTED                  LDAPError = 0x5c
	LDAP_OBJECT_CLASS_VIOLATION         LDAPError = 0x41
	LDAP_OPERATIONS_ERROR               LDAPError = 0x01
	LDAP_OTHER                          LDAPError = 0x50
	LDAP_PARAM_ERROR                    LDAPError = 0x59
	LDAP_PARTIAL_RESULTS                LDAPError = 0x09
	LDAP_PROTOCOL_ERROR                 LDAPError = 0x02
	LDAP_REFERRAL                       LDAPError = 0x0a
	LDAP_REFERRAL_LIMIT_EXCEEDED        LDAPError = 0x61
	LDAP_REFERRAL_V2                    LDAPError = 0x09
	LDAP_RESULTS_TOO_LARGE              LDAPError = 0x46
	LDAP_SERVER_DOWN                    LDAPError = 0x51
	LDAP_STRONG_AUTH_REQUIRED           LDAPError = 0x08
	LDAP_TIMELIMIT_EXCEEDED             LDAPError = 0x03
	LDAP_TIMEOUT                        LDAPError = 0x55
	LDAP_UNAVAILABLE                    LDAPError = 0x34
	LDAP_UNAVAILABLE_CRITICAL_EXTENSION LDAPError = 0x0c
	LDAP_UNDEFINED_TYPE                 LDAPError = 0x11
	LDAP_UNWILLING_TO_PERFORM           LDAPError = 0x35
	LDAP_USER_CANCELLED                 LDAPError = 0x58
	LDAP_VIRTUAL_LIST_VIEW_ERROR        LDAPError = 0x4c
)

type LDAPOption uint

const (
	LDAP_OPT_SIZELIMIT              LDAPOption = 0x03
	LDAP_OPT_HOST_NAME              LDAPOption = 0x30
	LDAP_OPT_HOST_REACHABLE         LDAPOption = 0x3e
	LDAP_OPT_PING_KEEP_ALIVE        LDAPOption = 0x36
	LDAP_OPT_PROTOCOL_VERSION       LDAPOption = 0x11
	LDAP_OPT_REFERRALS              LDAPOption = 0x08
	LDAP_OPT_PING_LIMIT             LDAPOption = 0x38
	LDAP_OPT_PING_WAIT_TIME         LDAPOption = 0x37
	LDAP_OPT_PROMPT_CREDENTIALS     LDAPOption = 0x3f
	LDAP_OPT_REF_DEREF_CONN_PER_MSG LDAPOption = 0x94
	LDAP_OPT_REFERRAL_CALLBACK      LDAPOption = 0x70
	LDAP_OPT_REFERRAL_HOP_LIMIT     LDAPOption = 0x10
	LDAP_OPT_ROOTDSE_CACHE          LDAPOption = 0x9a
	LDAP_OPT_SASL_METHOD            LDAPOption = 0x97
	LDAP_OPT_SECURITY_CONTEXT       LDAPOption = 0x99
	LDAP_OPT_SEND_TIMEOUT           LDAPOption = 0x42
	LDAP_OPT_SCH_FLAGS              LDAPOption = 0x43
	LDAP_OPT_SOCKET_BIND_ADDRESSES  LDAPOption = 0x44
	LDAP_OPT_SERVER_CERTIFICATE     LDAPOption = 0x81
	LDAP_OPT_SERVER_ERROR           LDAPOption = 0x33
	LDAP_OPT_SERVER_EXT_ERROR       LDAPOption = 0x34
	LDAP_OPT_SIGN                   LDAPOption = 0x95
	LDAP_OPT_SSL                    LDAPOption = 0x0a
	LDAP_OPT_SSL_INFO               LDAPOption = 0x93
	LDAP_OPT_SSPI_FLAGS             LDAPOption = 0x92
	LDAP_OPT_TCP_KEEPALIVE          LDAPOption = 0x40
	LDAP_OPT_TIMELIMIT              LDAPOption = 0x04
	LDAP_VERSION3                              = 3
)

type LDAPOptions struct {
	Domain         string   `json:"domain"`
	User           string   `json:"user"`
	Password       string   `json:"password"`
	AuthDomain     string   `json:"authdomain"`
	Servers        []string `json:"server"` // tries servers in this order
	SizeLimit      int      `json:"sizelimit"`
	Port           int16    `json:"port"`
	AuthMode       AuthMode `json:"authmode"`
	TLSMode        TLSmode  `json:"tlsmode"`
	Channelbinding bool     `json:"channelbinding"`
	IgnoreCert     bool     `json:"ignorecert"`
	Debug          bool     `json:"debug"`
}

func NewLDAPOptions() LDAPOptions {
	return LDAPOptions{}
}

type DomainDetector struct {
	Func func() string
	Name string
}

var (
	findDomain = []DomainDetector{
		{
			Name: "USERDNSDOMAIN",
			Func: func() string {
				return strings.ToLower(os.Getenv("USERDNSDOMAIN"))
			},
		},
		{
			Name: "FQDN",
			Func: func() string {
				f, err := fqdn.FqdnHostname()
				if err != nil {
					ui.Warn().Msgf("Autodetection using FQDN error: %v", err)
				} else if strings.Contains(f, ".") {
					return strings.ToLower(f[strings.Index(f, ".")+1:])
				}
				return ""
			},
		},
	}
)

func (ldo *LDAPOptions) Autodetect() error {
	if ldo.Port == 0 {
		if tlsmode == TLS {
			ldo.Port = 636
		} else {
			ldo.Port = 389
		}
	}
	if ldo.Domain == "" {
		ui.Info().Msg("No domain supplied, auto-detecting")
		for _, f := range findDomain {
			ldo.Domain = f.Func()
			if ldo.Domain != "" {
				ui.Info().Msgf("Detected domain as %v from %v", ldo.Domain, f.Name)
				break
			} else {
				ui.Warn().Msgf("Failed to detect domain with detector %v", f.Name)
			}
		}
	}
	if len(ldo.Servers) == 0 {
		if ldo.Domain == "" {
			return errors.New("Server auto-detection failed, we don't know the domain")
		}
		ui.Info().Msgf("Trying to auto-detect servers on domain '%v'", ldo.Domain)
		// Auto-detect server
		cname, dnsservers, err := net.LookupSRV("", "", "_ldap._tcp.dc._msdcs."+ldo.Domain)
		if err == nil && cname != "" && len(dnsservers) != 0 {
			for _, dnsserver := range dnsservers {
				ldo.Servers = append(ldo.Servers, strings.TrimRight(dnsserver.Target, "."))
			}
			ui.Info().Msgf("AD controller(s) detected as: %v", strings.Join(ldo.Servers, ", "))
		} else {
			return errors.New("AD controller auto-detection failed, use '--server' parameter")
		}
	}
	if runtime.GOOS != "windows" && ldo.User == "" && ldo.AuthMode != KerberosCache {
		// Auto-detect user
		ldo.User = os.Getenv("USERNAME")
		if ldo.User != "" {
			ui.Info().Msgf("Auto-detected username as %v", ldo.User)
		} else {
			return errors.New("Username autodetection failed - please use '--username' parameter")
		}
	}
	if ldo.AuthDomain == "" {
		ldo.AuthDomain = ldo.Domain
	}
	return nil
}

type objectCallbackFunc func(ro *activedirectory.RawObject) error
type DumpOptions struct {
	OnObject      objectCallbackFunc
	SearchBase    string
	Query         string
	WriteToFile   string
	Attributes    []string
	Scope         int
	ChunkSize     int
	NoSACL        bool
	ReturnObjects bool
}

func NewDumpOptions() DumpOptions {
	return DumpOptions{
		ChunkSize: 1000,
	}
}

type LDAPDumper interface {
	Connect() error
	Disconnect() error
	Dump(opts DumpOptions) ([]activedirectory.RawObject, error)
	Len() int // Number of objects in the dump (if known)
}

var CreateDumper = func(opts LDAPOptions) LDAPDumper {
	return &AD{
		LDAPOptions: opts,
	}
}
