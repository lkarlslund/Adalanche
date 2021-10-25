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
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	Command = &cobra.Command{
		Use:   "activedirectory",
		Short: "Dumps information from Active Directory",
	}

	autodetect = Command.Flags().Bool("autodetect", true, "Try to autodetect as much as we can, this will use environment variables and DNS to make this easy")

	server = Command.Flags().String("server", "", "DC to connect to, use IP or full hostname ex. -dc=\"dc.contoso.local\", random DC is auto-detected if not supplied")
	port   = Command.Flags().Int("port", 636, "LDAP port to connect to (389 or 636 typical)")
	domain = Command.Flags().String("domain", "", "domain suffix to analyze (contoso.local, auto-detected if not supplied)")
	user   = Command.Flags().String("username", "", "username to connect with (someuser@contoso.local)")
	pass   = Command.Flags().String("password", "", "password to connect with ex. --password hunter42")

	tlsmodeString = Command.Flags().String("tlsmode", "TLS", "Transport mode (TLS, StartTLS, NoTLS)")

	ignoreCert = Command.Flags().Bool("ignorecert", false, "Disable certificate checks")

	authmodeString *string

	authdomain = Command.Flags().String("authdomain", "", "domain for authentication, if using ntlm auth")
	dumpquery  = Command.Flags().String("query", "(objectClass=*)", "LDAP query for dump, defaults to everything")

	attributesparam = Command.Flags().String("attributes", "*", "Comma seperated list of attributes to get, * = all, or a comma seperated list of attribute names (expert)")

	nosacl   = Command.Flags().Bool("nosacl", true, "Request data with NO SACL flag, allows normal users to dump ntSecurityDescriptor field")
	pagesize = Command.Flags().Int("pagesize", 1000, "Number of objects per request to collect (increase for performance, but some DCs have limits)")

	collectconfiguration = Command.Flags().Bool("configuration", true, "Collect Active Directory Configuration")
	collectschema        = Command.Flags().Bool("schema", true, "Collect Active Directory Schema")
	collectdns           = Command.Flags().Bool("dns", true, "Collect Active Directory Integrated DNS zones")
	collectobjects       = Command.Flags().Bool("objects", true, "Collect Active Directory Objects (users, groups etc)")
	collectgpos          = Command.Flags().Bool("gpos", true, "Collect Group Policy file contents")
	gpopath              = Command.Flags().String("gpopath", "", "Override path to GPOs, useful for non Windows OS'es with mounted drive (/mnt/policies/ or similar), but will break ACL feature")

	username string // UPN style name
	// Local authmod as a byte
	authmode byte
	tlsmode  TLSmode
)

func init() {
	defaultmode := "ntlm"
	if runtime.GOOS == "windows" {
		defaultmode = "ntlmsspi"
	}
	authmodeString = Command.Flags().String("authmode", defaultmode, "Bind mode: unauth, simple, md5, ntlm, ntlmpth (password is hash), ntlmsspi (current user, default)")

	clicollect.Collect.AddCommand(Command)
	Command.PreRunE = PreRun
	Command.RunE = Execute
}

// Checks that we have enough data to proceed with the real run
func PreRun(cmd *cobra.Command, args []string) error {
	// Auto detect domain if not supplied
	if *autodetect {

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

		if *domain != "" && *server == "" {
			// Auto-detect server
			cname, servers, err := net.LookupSRV("", "", "_ldap._tcp.dc._msdcs."+*domain)
			if err == nil && cname != "" && len(servers) != 0 {
				*server = strings.TrimRight(servers[0].Target, ".")
				log.Info().Msgf("AD controller detected as: %v", *server)
			} else {
				return errors.New("AD controller auto-detection failed, use '--server' parameter")
			}
		}
	}

	var err error
	tlsmode, err = TLSmodeString(*tlsmodeString)
	if err != nil {
		return fmt.Errorf("Unknown TLS mode %v", tlsmode)
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

	if *autodetect && authmode != 5 && *user == "" {
		// Auto-detect user
		*user = os.Getenv("USERNAME")
		if *user != "" {
			log.Info().Msgf("Auto-detected username as %v", *user)
		} else {
			return errors.New("Username autodetection failed - please use '--username' parameter")
		}
	}

	if len(*domain) == 0 {
		return errors.New("missing domain name  - please provide this on commandline")
	}

	if len(*server) == 0 {
		return errors.New("missing AD controller server name - please provide this on commandline")
	}

	if authmode != 5 {
		if *user == "" {
			return errors.New("Missing username - please use '--username' parameter")
		}

		if *pass == "" {
			fmt.Printf("Please enter password for %v: ", *user)
			passwd, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err == nil {
				*pass = string(passwd)
			}
		}

		username = *user

		if !strings.Contains(username, "@") && !strings.Contains(username, "\\") {
			username = username + "@" + *domain
			log.Info().Msgf("Username does not contain @ or \\, auto expanding it to %v", username)
		}
	} else {
		log.Info().Msg("Using integrated NTLM authentication")
	}

	return nil
}

func Execute(cmd *cobra.Command, args []string) error {
	ad := AD{
		Domain:     *domain,
		Server:     *server,
		Port:       uint16(*port),
		User:       username,
		Password:   *pass,
		AuthDomain: *authdomain,
		TLSMode:    tlsmode,
		IgnoreCert: *ignoreCert,
	}

	err := ad.Connect(authmode)
	if err != nil {
		return errors.Wrap(err, "problem connecting to AD")
	}

	var attributes []string
	switch *attributesparam {
	// case "":
	// 	return errors.New("I don't know how to interpret attributes (blank?)")
	case "*":

	// case "needed":
	default:
		attributes = strings.Split(*attributesparam, ",")
	}

	datapath := cmd.Flag("datapath").Value.String()

	do := DumpOptions{
		Attributes:    attributes,
		NoSACL:        *nosacl,
		ChunkSize:     *pagesize,
		ReturnObjects: false,
	}

	if *collectschema {
		log.Info().Msg("Collecting schema objects ...")
		do.SearchBase = "CN=Schema,CN=Configuration," + ad.RootDn()
		do.WriteToFile = filepath.Join(datapath, do.SearchBase+".objects.msgp.lz4")
		_, err = ad.Dump(do)
		if err != nil {
			os.Remove(do.WriteToFile)
			return fmt.Errorf("problem collecting Active Directory schema objects: %v", err)
		}
	}

	if *collectconfiguration {
		log.Info().Msg("Collecting configuration objects ...")
		do.SearchBase = "CN=Configuration," + ad.RootDn()
		do.WriteToFile = filepath.Join(datapath, do.SearchBase+".objects.msgp.lz4")
		_, err = ad.Dump(do)
		if err != nil {
			os.Remove(do.WriteToFile)
			return fmt.Errorf("problem collecting Active Directory configuration objects: %v", err)
		}
	}

	if *collectdns {
		log.Info().Msg("Collecting forest DNS objects ...")
		do.SearchBase = "DC=ForestDnsZones," + ad.RootDn()
		do.WriteToFile = filepath.Join(datapath, do.SearchBase+".objects.msgp.lz4")
		_, err = ad.Dump(do)
		if err != nil {
			os.Remove(do.WriteToFile)
			return fmt.Errorf("problem collecting Active Directory Forest DNS objects: %v", err)
		}

		log.Info().Msg("Collecting domain DNS objects ...")
		do.SearchBase = "DC=DomainDnsZones," + ad.RootDn()
		do.WriteToFile = filepath.Join(datapath, do.SearchBase+".objects.msgp.lz4")
		_, err = ad.Dump(do)
		if err != nil {
			os.Remove(do.WriteToFile)
			return fmt.Errorf("problem collecting Active Directory Domain DNS objects: %v", err)
		}
	}

	var gpostocollect []*activedirectory.RawObject

	if *collectobjects {
		log.Info().Msg("Collecting main AD objects ...")
		do.SearchBase = ad.RootDn()
		do.WriteToFile = filepath.Join(datapath, do.SearchBase+".objects.msgp.lz4")

		if *collectgpos {
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

	if *collectgpos {
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
		return fmt.Errorf("Problem disconnecting from AD: %v", err)
	}

	return nil
}
