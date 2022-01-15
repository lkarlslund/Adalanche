package collect

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/pkg/errors"

	"github.com/Showmax/go-fqdn"
	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/basedata"
	clicollect "github.com/lkarlslund/adalanche/modules/cli/collect"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	ldap "github.com/lkarlslund/ldap/v3"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	Command = &cobra.Command{
		Use:   "activedirectory",
		Short: "Collects information from Active Directory",
	}

	autodetect = Command.Flags().Bool("autodetect", true, "Try to autodetect as much as we can, this will use environment variables and DNS to make this easy")

	server = Command.Flags().String("server", "", "DC to connect to, use IP or full hostname ex. -dc=\"dc.contoso.local\", random DC is auto-detected if not supplied")
	port   = Command.Flags().Int("port", 636, "LDAP port to connect to (389 or 636 typical)")
	domain = Command.Flags().String("domain", "", "domain suffix to analyze (contoso.local, auto-detected if not supplied)")
	user   = Command.Flags().String("username", "", "username to connect with (someuser@contoso.local)")
	pass   = Command.Flags().String("password", "", "password to connect with ex. --password hunter42")

	tlsmodeString = Command.Flags().String("tlsmode", "TLS", "Transport mode (TLS, StartTLS, NoTLS)")

	ignoreCert = Command.Flags().Bool("ignorecert", false, "Disable certificate checks")

	ldapdebug = Command.Flags().Bool("ldapdebug", false, "Enable LDAP debugging")

	authmodeString *string

	authdomain      = Command.Flags().String("authdomain", "", "domain for authentication, if using ntlm auth")
	attributesparam = Command.Flags().String("attributes", "*", "Comma seperated list of attributes to get, * = all, or a comma seperated list of attribute names (expert)")

	nosacl   = Command.Flags().Bool("nosacl", true, "Request data with NO SACL flag, allows normal users to dump ntSecurityDescriptor field")
	pagesize = Command.Flags().Int("pagesize", 1000, "Number of objects per request to collect (increase for performance, but some DCs have limits)")

	collectconfiguration = Command.Flags().String("configuration", "auto", "Collect Active Directory Configuration")
	collectschema        = Command.Flags().String("schema", "auto", "Collect Active Directory Schema")
	collectother         = Command.Flags().String("other", "auto", "Collect other Active Directory contexts (typically integrated DNS zones)")
	collectobjects       = Command.Flags().String("objects", "auto", "Collect Active Directory Objects (users, groups etc)")
	collectgpos          = Command.Flags().String("gpos", "auto", "Collect Group Policy file contents")
	gpopath              = Command.Flags().String("gpopath", "", "Override path to GPOs, useful for non Windows OS'es with mounted drive (/mnt/policies/ or similar), but will break ACL feature")

	// Local authmod as a byte
	authmode byte
	tlsmode  TLSmode
)

func init() {
	defaultmode := "ntlm"
	if runtime.GOOS == "windows" {
		defaultmode = "ntlmsspi"
	}
	authmodeString = Command.Flags().String("authmode", defaultmode, "Bind mode: unauth, simple, md5, ntlm, ntlmpth (password is hash), ntlmsspi (integrated Windows)")

	clicollect.Collect.AddCommand(Command)
	Command.PreRunE = PreRun
	Command.RunE = Execute
}

// Checks that we have enough data to proceed with the real run
func PreRun(cmd *cobra.Command, args []string) error {
	var err error
	tlsmode, err = TLSmodeString(*tlsmodeString)
	if err != nil {
		return fmt.Errorf("unknown TLS mode %v", tlsmode)
	}

	switch strings.ToLower(*authmodeString) {
	case "unauth":
		authmode = 0
	case "simple":
		authmode = 1
	case "md5":
		authmode = 2
	case "ntlm":
		authmode = 3
	case "ntlmpth":
		authmode = 4
	case "ntlmsspi":
		authmode = 5
	default:
		return fmt.Errorf("unknown LDAP authentication mode %v", authmodeString)
	}

	// AUTODETECTION

	if *autodetect {
		if *server == "" {

			// We only need to auto-detect the domain if the server is not supplied
			if *domain == "" {
				log.Info().Msg("No domain supplied, auto-detecting")
				*domain = strings.ToLower(os.Getenv("USERDNSDOMAIN"))
				if *domain == "" {
					// That didn't work, lets try something else
					f, err := fqdn.FqdnHostname()
					if err == nil && strings.Contains(f, ".") {
						log.Info().Msg("No USERDNSDOMAIN set - using machines FQDN as basis")
						*domain = strings.ToLower(f[strings.Index(f, ".")+1:])
					}
				}
				if *domain == "" {
					return errors.New("Domain auto-detection failed")
				} else {
					log.Info().Msgf("Auto-detected domain as %v", *domain)
				}
			}

			if *server == "" {
				// Auto-detect server
				cname, servers, err := net.LookupSRV("", "", "_ldap._tcp.dc._msdcs."+*domain)
				if err == nil && cname != "" && len(servers) != 0 {
					*server = strings.TrimRight(servers[0].Target, ".")
					log.Info().Msgf("AD controller detected as: %v", *server)
				} else {
					return errors.New("AD controller auto-detection failed, use '--server' parameter")
				}
			}

			if authmode != 5 && *user == "" {
				// Auto-detect user
				*user = os.Getenv("USERNAME")
				if *user != "" {
					log.Info().Msgf("Auto-detected username as %v", *user)
				} else {
					return errors.New("Username autodetection failed - please use '--username' parameter")
				}
			}
		}
	}

	// END OF AUTODETECTION

	if len(*server) == 0 {
		return errors.New("missing AD controller server name - please provide this on commandline")
	}

	if authmode == 5 && *pass != "" {
		return errors.New("You supplied a password, but authmode is set to NTMLSSPI (integrated authentication). Please change authmode or do not supply a password")
	}

	if authmode != 5 {
		if *user == "" {
			return errors.New("Missing username - please use '--username' parameter")
		}

		if authmode != 3 {
			if *domain != "" && !strings.Contains(*user, "@") && !strings.Contains(*user, "\\") {
				*user = *user + "@" + *domain
				log.Info().Msgf("Username does not contain @ or \\, auto expanding it to %v", *user)
			}
		}
	} else {
		log.Info().Msg("Using integrated NTLM authentication")
	}

	if authmode != 5 {
		if *pass == "" {
			fmt.Printf("Please enter password for %v: ", *user)
			passwd, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err == nil {
				*pass = string(passwd)
			}
		}
	}

	if authmode == 3 {
		if *authdomain == "" {
			return errors.New("Missing authdomain for NTLM - please use '--authdomain' parameter")
		}
	}

	return nil
}

func Execute(cmd *cobra.Command, args []string) error {
	ad := AD{
		Domain:     *domain,
		Server:     *server,
		Port:       uint16(*port),
		User:       *user,
		Password:   *pass,
		AuthDomain: *authdomain,
		TLSMode:    tlsmode,
		IgnoreCert: *ignoreCert,
		Debug:      *ldapdebug,
	}

	err := ad.Connect(authmode)
	if err != nil {
		return errors.Wrap(err, "problem connecting to AD")
	}

	var attributes []string
	switch *attributesparam {
	case "*":
		// don't do anything
	default:
		attributes = strings.Split(*attributesparam, ",")
	}

	datapath := "data"
	if idp := cmd.InheritedFlags().Lookup("datapath"); idp != nil {
		datapath = idp.Value.String()
	}

	log.Info().Msg("Probing RootDSE ...")
	rootdse, err := ad.Dump(DumpOptions{
		SearchBase:    "",
		Scope:         ldap.ScopeBaseObject,
		ReturnObjects: true,
	})
	if err != nil {
		return fmt.Errorf("problem querying Active Directory RootDSE: %w", err)
	}
	if len(rootdse) != 1 {
		return fmt.Errorf("expected 1 Active Directory RootDSE object, but got %v", len(rootdse))
	}
	rd := rootdse[0]

	namingcontexts := map[string]bool{}
	for _, context := range rd.Attributes["namingContexts"] {
		namingcontexts[context] = false
	}

	configContext := rd.Attributes["configurationNamingContext"][0]
	namingcontexts[configContext] = true
	domainContext := rd.Attributes["defaultNamingContext"][0]
	namingcontexts[domainContext] = true
	rootDomainContext := rd.Attributes["rootDomainNamingContext"][0]
	namingcontexts[rootDomainContext] = true
	schemaContext := rd.Attributes["schemaNamingContext"][0]
	namingcontexts[schemaContext] = true

	var otherContexts []string
	for context, used := range namingcontexts {
		if !used {
			otherContexts = append(otherContexts, context)
		}
	}

	log.Info().Msg("Saving RootDSE ...")
	_, err = ad.Dump(DumpOptions{
		SearchBase:  "",
		Scope:       ldap.ScopeBaseObject,
		WriteToFile: filepath.Join(datapath, domainContext+".RootDSE.objects.msgp.lz4"),
	})
	if err != nil {
		return fmt.Errorf("problem saving Active Directory RootDSE: %w", err)
	}

	do := DumpOptions{
		Attributes:    attributes,
		Scope:         ldap.ScopeWholeSubtree,
		NoSACL:        *nosacl,
		ChunkSize:     *pagesize,
		ReturnObjects: false,
	}

	cs, _ := util.ParseBool(*collectschema)
	if (*collectschema == "auto" && schemaContext != "") || cs {
		log.Info().Msg("Collecting schema objects ...")
		do.SearchBase = schemaContext
		do.WriteToFile = filepath.Join(datapath, do.SearchBase+".objects.msgp.lz4")
		_, err = ad.Dump(do)
		if err != nil {
			os.Remove(do.WriteToFile)
			return fmt.Errorf("problem collecting Active Directory schema objects: %v", err)
		}
	}

	cs, _ = util.ParseBool(*collectconfiguration)
	if (*collectconfiguration == "auto" && configContext != "") || cs {
		log.Info().Msg("Collecting configuration objects ...")
		do.SearchBase = configContext
		do.WriteToFile = filepath.Join(datapath, do.SearchBase+".objects.msgp.lz4")
		_, err = ad.Dump(do)
		if err != nil {
			os.Remove(do.WriteToFile)
			return fmt.Errorf("problem collecting Active Directory configuration objects: %v", err)
		}
	}

	cs, _ = util.ParseBool(*collectother)
	if (*collectother == "auto" && len(otherContexts) > 0) || cs {
		log.Info().Msg("Collecting other objects ...")
		for _, context := range otherContexts {
			log.Info().Msgf("Collecting from base DN %v ...", context)
			do.SearchBase = context
			do.WriteToFile = filepath.Join(datapath, do.SearchBase+".objects.msgp.lz4")
			_, err = ad.Dump(do)
			if err != nil {
				os.Remove(do.WriteToFile)
				return fmt.Errorf("problem collecting Active Directory Forest DNS objects: %v", err)
			}
		}
	}

	var gpostocollect []*activedirectory.RawObject

	cs, _ = util.ParseBool(*collectobjects)
	if (*collectobjects == "auto" && domainContext != "") || cs {
		log.Info().Msg("Collecting main AD objects ...")
		do.SearchBase = domainContext
		do.WriteToFile = filepath.Join(datapath, do.SearchBase+".objects.msgp.lz4")

		cp, _ := util.ParseBool(*collectgpos)
		if *collectgpos == "auto" || cp {
			do.OnObject = func(ro *activedirectory.RawObject) error {
				if _, found := ro.Attributes["gPCFileSysPath"]; found {
					gpostocollect = append(gpostocollect, ro)
				}
				return nil
			}
		}

		_, err = ad.Dump(do)
		if err != nil {
			os.Remove(do.WriteToFile)
			return fmt.Errorf("problem collecting Active Directory objects: %v", err)
		}
	}

	cp, _ := util.ParseBool(*collectgpos)
	if *collectgpos == "auto" || cp {
		log.Debug().Msg("Collecting GPO files ...")
		if *gpopath != "" {
			log.Warn().Msg("Disabling GPO file ACL detection on overridden GPO path")
		}
		for _, object := range gpostocollect {
			// Let's check if it this is a GPO and then add som fake attributes to represent it
			if gpfsp, found := object.Attributes["gPCFileSysPath"]; found {

				gpodisplayname := object.Attributes["displayName"]
				gpoguid := object.Attributes["name"]
				originalpath := gpfsp[0]

				gppath := originalpath
				if *gpopath != "" {
					if len(gpoguid) != 1 {
						log.Warn().Msgf("GPO %v GUID not readable, skipping", gpodisplayname)
						continue
					}

					gppath = filepath.Join(*gpopath, gpoguid[0])
				}
				log.Info().Msgf("Collecting group policy files from %v ...", gppath)

				_, err := os.Stat(gppath)
				if err != nil {
					log.Warn().Msg("Can't access path, aborting this GPO ...")
				} else {
					gpoinfo := activedirectory.GPOdump{
						Common: basedata.GetCommonData(),
					}

					gpuuid, _ := uuid.FromString(gpoguid[0])

					gpoinfo.GPOinfo.GUID = gpuuid
					gpoinfo.GPOinfo.Path = originalpath // The original path is kept, we don't care

					offset := len(gppath)
					filepath.WalkDir(gppath, func(curpath string, d fs.DirEntry, err error) error {
						if !d.IsDir() &&
							(strings.HasSuffix(strings.ToLower(curpath), ".adm") || strings.HasSuffix(strings.ToLower(curpath), ".admx")) {
							// Skip .adm(x) files that slipped in here
							return nil
						}

						var fileinfo activedirectory.GPOfileinfo
						fileinfo.IsDir = d.IsDir()
						fileinfo.RelativePath = curpath[offset:]

						if gppath == originalpath {
							// Do file ACL analysis if we're reading directly from SYSVOL
							owner, dacl, err := windowssecurity.GetOwnerAndDACL(curpath, windowssecurity.SE_FILE_OBJECT)
							if err == nil {
								fileinfo.OwnerSID = owner
								fileinfo.DACL = dacl
							} else {
								log.Warn().Msgf("Problem getting %v DACL: %v", curpath, err)
							}
						}
						if !d.IsDir() {
							rawfile, err := ioutil.ReadFile(curpath)
							if err == nil {
								fileinfo.Contents = rawfile
							} else {
								log.Warn().Msgf("Problem getting %v contents: %v", curpath, err)
							}
						}
						gpoinfo.GPOinfo.Files = append(gpoinfo.GPOinfo.Files, fileinfo)
						return nil
					})

					gpodatafile := filepath.Join(datapath, gpoguid[0]+".gpodata.json")
					f, err := os.Create(gpodatafile)
					if err != nil {
						log.Error().Msgf("Problem writing GPO information to %v: %v")
					}
					defer f.Close()

					err = json.NewEncoder(f).Encode(gpoinfo)
					if err != nil {
						log.Error().Msgf("Problem marshalling GPO information to %v: %v", gpodatafile, err)
					}
				}
			}
		}
	}

	err = ad.Disconnect()
	if err != nil {
		return fmt.Errorf("problem disconnecting from AD: %v", err)
	}

	return nil
}
