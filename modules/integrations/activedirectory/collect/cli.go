package collect

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/lkarlslund/adalanche/modules/cli"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/pkg/errors"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/adalanche/modules/basedata"
	clicollect "github.com/lkarlslund/adalanche/modules/cli/collect"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/util"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	ldap "github.com/lkarlslund/ldap/v3"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	Command = &cobra.Command{
		Use:   "activedirectory",
		Short: "Collects information from Active Directory",
	}

	autodetect = Command.Flags().Bool("autodetect", true, "Try to autodetect as much as we can, this will use environment variables and DNS to make this easy")

	adexplorerfile  = Command.Flags().String("adexplorerfile", "", "Import AD objects from SysInternals ADexplorer dump")
	adexplorerboost = Command.Flags().Bool("adexplorerboost", true, "Boost ADexplorer performance by using loading the binary file into RAM before decoding it")

	ntdsfile = Command.Flags().String("ntdsfile", "", "Import AD objects from NTDS.DIT file")

	servers = Command.Flags().StringArray("server", nil, "DC to connect to, use IP or full hostname, random DC is auto-detected if not supplied")
	port    = Command.Flags().Int("port", 0, "LDAP port to connect to (389 or 636 typical, 0 for automatic port based on tlsmode)")
	domain  = Command.Flags().String("domain", "", "domain suffix to analyze (auto-detected if not supplied)")
	user    = Command.Flags().String("username", "", "username to connect with")
	pass    = Command.Flags().String("password", "", "password to connect with (use ! for blank password)")

	tlsmodeString  = Command.Flags().String("tlsmode", "NoTLS", "Transport mode (TLS, StartTLS, NoTLS)")
	channelbinding = Command.Flags().Bool("channelbinding", true, "Enable channel binding when connecting to LDAP")
	ignoreCert     = Command.Flags().Bool("ignorecert", false, "Disable certificate checks")

	ldapdebug = Command.Flags().Bool("ldapdebug", false, "Enable LDAP debugging")

	authdomain      = Command.Flags().String("authdomain", "", "domain for authentication, if using ntlm auth")
	attributesparam = Command.Flags().String("attributes", "*", "Comma seperated list of attributes to get, * = all, or a comma seperated list of attribute names (expert)")

	nosacl   = Command.Flags().Bool("nosacl", true, "Request data with NO SACL flag, allows normal users to dump ntSecurityDescriptor field")
	pagesize = Command.Flags().Int("pagesize", 1000, "Number of objects per request to collect (increase for performance, but some DCs have limits)")

	objectquery = Command.Flags().String("obfuscatedquery", "(objectclass=*)", "Change query from (objectclass=*) to something different in order to evade detection")

	collectconfiguration = Command.Flags().String("configuration", "auto", "Collect Active Directory Configuration")
	collectschema        = Command.Flags().String("schema", "auto", "Collect Active Directory Schema")
	collectother         = Command.Flags().String("other", "auto", "Collect other Active Directory contexts (typically integrated DNS zones)")
	collectobjects       = Command.Flags().String("objects", "auto", "Collect Active Directory Objects (users, groups etc)")
	collectgpos          = Command.Flags().String("gpos", "auto", "Collect Group Policy file contents")
	gpopath              = Command.Flags().String("gpopath", "", "Override path to GPOs, useful for non Windows OS'es with mounted drive (/mnt/policies/ or similar), but will break ACL feature")
	AuthmodeString       = Command.Flags().String("authmode", "ntlm", "Bind mode: unauth/anonymous, basic/simple, digest/md5, kerberoscache, ntlm, ntlmpth (password is hash)")

	purgeolddata = Command.Flags().Bool("purgeolddata", false, "Purge existing data from the datapath if connection to DC is successfull")

	authmode AuthMode
	tlsmode  TLSmode
	options  LDAPOptions
)

func init() {

	clicollect.Collect.AddCommand(Command)
	Command.PreRunE = PreRun
	Command.RunE = Execute
}

// Checks that we have enough data to proceed with the real run
func PreRun(cmd *cobra.Command, args []string) error {
	if *adexplorerfile != "" || *ntdsfile != "" {
		// That's all we need for this run to work
		return nil
	}

	var err error
	tlsmode, err = TLSmodeString(*tlsmodeString)
	if err != nil {
		return fmt.Errorf("unknown TLS mode %v", tlsmode)
	}

	authmode, err = AuthModeString(*AuthmodeString)
	if err != nil {
		return fmt.Errorf("unknown auth mode %v", authmode)
	}

	// AUTODETECTION
	options = LDAPOptions{
		Servers:        *servers,
		Port:           int16(*port),
		AuthMode:       authmode,
		User:           *user,
		Password:       *pass,
		Domain:         *domain,
		AuthDomain:     *authdomain,
		TLSMode:        tlsmode,
		IgnoreCert:     *ignoreCert,
		Debug:          *ldapdebug,
		Channelbinding: *channelbinding,
	}

	if *autodetect {
		err := options.Autodetect()
		if err != nil {
			ui.Warn().Msgf("Problem doing auto-detection: %v", err)
		}
	}

	// END OF AUTODETECTION
	if len(options.Servers) == 0 {
		return errors.New("missing AD controller server name - please provide this on commandline")
	}

	if authmode == KerberosCache {
		// Assume we can find the cache file later on
		return nil
	}

	if options.User == "" {
		if options.Password != "" {
			return errors.New("You supplied a password, but not a username. Please provide a username or do not supply a password")
		}

		if runtime.GOOS != "windows" {
			return errors.New("You need to supply a username and password for platforms other than Windows")
		}
	} else {
		if options.Password == "" {
			fmt.Printf("Please enter password for %v: ", *user)
			passwd, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err == nil {
				options.Password = string(passwd)
			}
		}

		if options.Password == "!" {
			// A single ! indicates we want to use a blank password, so lets change it to that
			options.Password = ""
		}

		// if authmode == NTLM {
		// 	if *authdomain == "" {
		// 		return errors.New("Missing authdomain for NTLM - please use '--authdomain' parameter")
		// 	}
		// }
	}

	return nil
}

func Execute(cmd *cobra.Command, args []string) error {
	datapath := *cli.Datapath

	cp, _ := util.ParseBool(*collectgpos)
	var gpostocollect []*activedirectory.RawObject
	var netbiosname string

	if *adexplorerfile != "" {
		// Active Directory Explorer file
		ui.Info().Msgf("Collecting objects from AD Explorer snapshot %v ...", *adexplorerfile)

		ad := ADExplorerDumper{
			path:        *adexplorerfile,
			performance: *adexplorerboost,
		}

		err := ad.Connect()
		if err != nil {
			return err
		}

		do := DumpOptions{
			ReturnObjects: false,
			WriteToFile:   filepath.Join(datapath, filepath.Base(*adexplorerfile)+".objects.msgp.lz4"),
		}

		if *collectgpos == "auto" || cp {
			do.OnObject = func(ro *activedirectory.RawObject) error {
				if _, found := ro.Attributes["gPCFileSysPath"]; found {
					gpostocollect = append(gpostocollect, ro)
				}
				if nbn, found := ro.Attributes["nETBIOSName"]; found {
					netbiosname = nbn[0]
				}
				return nil
			}
		}

		_, err = ad.Dump(do)
		if err != nil {
			os.Remove(do.WriteToFile)
			return fmt.Errorf("problem collecting Active Directory objects: %v", err)
		}

		err = ad.Disconnect()
		if err != nil {
			return err
		}
	} else if *ntdsfile != "" {
		// Active Directory Explorer file
		ui.Info().Msgf("Collecting objects from NTDS.DIT file %v ...", *ntdsfile)

		ad := NTDSDumper{
			path: *ntdsfile,
		}

		err := ad.Connect()
		if err != nil {
			return err
		}

		do := DumpOptions{
			// ReturnObjects: true,
			WriteToFile: filepath.Join(datapath, filepath.Base(*ntdsfile)+".objects.msgp.lz4"),
		}

		cp, _ := util.ParseBool(*collectgpos)
		if *collectgpos == "auto" || cp {
			do.OnObject = func(ro *activedirectory.RawObject) error {
				if _, found := ro.Attributes["gPCFileSysPath"]; found {
					gpostocollect = append(gpostocollect, ro)
				}
				if nbn, found := ro.Attributes["nETBIOSName"]; found {
					netbiosname = nbn[0]
				}
				return nil
			}
		}

		// err = ad.DebugDump()
		objects, err := ad.Dump(do)
		if len(objects) > 0 {
			debugfilename := do.WriteToFile + ".json"
			ui.Debug().Msgf("Writing %v debug objects to %v", len(objects), debugfilename)
			jsondata, _ := json.MarshalIndent(objects, "", "  ")
			os.WriteFile(debugfilename, jsondata, 0644)
		}

		if err != nil {
			os.Remove(do.WriteToFile)
			return fmt.Errorf("problem collecting Active Directory objects: %v", err)
		}

		ad.Disconnect()
	} else {
		// Active Directory dump directly from AD controller
		var ad LDAPDumper

		// Find usable DC from list of servers
		ad = CreateDumper(options)

		err := ad.Connect()
		if err != nil {
			return fmt.Errorf("all DCs failed, last error: %v", err)
		}

		var attributes []string
		switch *attributesparam {
		case "*":
			// don't do anything
		default:
			attributes = strings.Split(*attributesparam, ",")
		}

		ui.Info().Msg("Probing RootDSE ...")
		do := DumpOptions{
			SearchBase:    "",
			Query:         *objectquery,
			Scope:         ldap.ScopeBaseObject,
			ReturnObjects: true,
		}

		rootdse, err := ad.Dump(do)
		if err != nil {
			return fmt.Errorf("problem querying Active Directory RootDSE: %w", err)
		}
		if len(rootdse) != 1 {
			return fmt.Errorf("expected 1 Active Directory RootDSE object, but got %v", len(rootdse))
		}

		var domainContext string

		rd := rootdse[0]

		namingcontexts := map[string]bool{}
		for _, context := range rd.Attributes["namingContexts"] {
			namingcontexts[context] = false
		}

		var configContext string
		if len(rd.Attributes["configurationNamingContext"]) > 0 {
			configContext = rd.Attributes["configurationNamingContext"][0]
			namingcontexts[configContext] = true
		}

		if len(rd.Attributes["defaultNamingContext"]) > 0 {
			domainContext = rd.Attributes["defaultNamingContext"][0]
			namingcontexts[domainContext] = true
		}

		var rootDomainContext string
		if len(rd.Attributes["rootDomainNamingContext"]) > 0 {
			rootDomainContext = rd.Attributes["rootDomainNamingContext"][0]
			namingcontexts[rootDomainContext] = true
		}

		var schemaContext string
		if len(rd.Attributes["schemaNamingContext"]) > 0 {
			schemaContext = rd.Attributes["schemaNamingContext"][0]
			namingcontexts[schemaContext] = true
		}

		var otherContexts []string
		for context, used := range namingcontexts {
			if !used {
				otherContexts = append(otherContexts, context)
			}
		}

		// Auto adjust this to local domain, most users don't understand that each domain needs it's own path
		if datapath == "data" {
			datapath = filepath.Join("data", domainContext)
		}

		// Clean up old data if requested
		if _, err := os.Stat(datapath); err == nil && *purgeolddata {
			ui.Info().Msgf("Removing old data from %v", datapath)
			os.RemoveAll(datapath)
		}

		// Ensure output folder exists
		if _, err := os.Open(datapath); os.IsNotExist(err) {
			err = os.MkdirAll(datapath, 0755)
			if err != nil {
				return err
			}
		}

		ui.Info().Msg("Saving RootDSE ...")
		_, err = ad.Dump(DumpOptions{
			SearchBase:  "",
			Scope:       ldap.ScopeBaseObject,
			WriteToFile: filepath.Join(datapath, domainContext+".RootDSE.objects.msgp.lz4"),
		})
		if err != nil {
			return fmt.Errorf("problem saving Active Directory RootDSE: %w", err)
		}

		if len(rootdse) != 1 {
			ui.Error().Msgf("Expected 1 Active Directory RootDSE object, but got %v", len(rootdse))
		}

		do = DumpOptions{
			Attributes:    attributes,
			Query:         *objectquery,
			Scope:         ldap.ScopeWholeSubtree,
			NoSACL:        *nosacl,
			ChunkSize:     *pagesize,
			ReturnObjects: false,
		}

		cs, _ := util.ParseBool(*collectschema)
		if (*collectschema == "auto" && schemaContext != "") || cs {
			ui.Info().Msgf("Collecting schema objects from %v ...", schemaContext)
			do.SearchBase = schemaContext
			do.WriteToFile = filepath.Join(datapath, do.SearchBase+".objects.msgp.lz4")
			_, err = ad.Dump(do)
			if err != nil {
				os.Remove(do.WriteToFile)
				return fmt.Errorf("problem collecting Active Directory schema objects: %v", err)
			}
			ui.Info().Msgf("Collected %v objects from schema context", ad.Len())
		}

		cs, _ = util.ParseBool(*collectconfiguration)
		if (*collectconfiguration == "auto" && configContext != "") || cs {
			ui.Info().Msgf("Collecting configuration objects from %v ...", configContext)
			do.SearchBase = configContext
			do.WriteToFile = filepath.Join(datapath, do.SearchBase+".objects.msgp.lz4")

			if *collectgpos == "auto" || cp {
				do.OnObject = func(ro *activedirectory.RawObject) error {
					if nbn, found := ro.Attributes["nETBIOSName"]; found {
						netbiosname = nbn[0]
					}
					return nil
				}
			}

			_, err = ad.Dump(do)
			if err != nil {
				os.Remove(do.WriteToFile)
				return fmt.Errorf("problem collecting Active Directory configuration objects: %v", err)
			}
			ui.Info().Msgf("Collected %v objects from configuration context", ad.Len())
		}

		cs, _ = util.ParseBool(*collectother)
		if (*collectother == "auto" && len(otherContexts) > 0) || cs {
			ui.Info().Msgf("Collecting from %v other contexts", len(otherContexts))
			for _, context := range otherContexts {
				ui.Info().Msgf("Collecting from base DN %v ...", context)
				do.SearchBase = context
				do.WriteToFile = filepath.Join(datapath, do.SearchBase+".objects.msgp.lz4")

				_, err = ad.Dump(do)
				if err != nil {
					os.Remove(do.WriteToFile)
					return fmt.Errorf("problem collecting Active Directory Forest DNS objects: %v", err)
				}
				ui.Info().Msgf("Collected %v objects from base DN %v", ad.Len(), context)
			}
		}

		cs, _ = util.ParseBool(*collectobjects)
		if (*collectobjects == "auto" && domainContext != "") || cs {
			ui.Info().Msgf("Collecting main AD objects from %v ...", domainContext)
			do.SearchBase = domainContext
			do.WriteToFile = filepath.Join(datapath, do.SearchBase+".objects.msgp.lz4")

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

		err = ad.Disconnect()
		if err != nil {
			return fmt.Errorf("problem disconnecting from AD: %v", err)
		}
	}

	if *collectgpos == "auto" || cp {
		ui.Debug().Msg("Collecting GPO files ...")
		if *gpopath != "" {
			ui.Warn().Msg("Disabling GPO file ACL detection on overridden GPO path")
		}
		for _, object := range gpostocollect {
			// Let's check if it this is a GPO and then add som fake attributes to represent it
			if gpfsp, found := object.Attributes["gPCFileSysPath"]; found {
				domainContext := util.ExtractDomainContextFromDistinguishedName(object.DistinguishedName)

				gpodisplayname := object.Attributes["displayName"]
				gpoguid := object.Attributes["name"]
				originalpath := gpfsp[0]

				gppath := originalpath
				if *gpopath != "" {
					if len(gpoguid) != 1 {
						ui.Warn().Msgf("GPO %v GUID not readable, skipping", gpodisplayname)
						continue
					}

					gppath = filepath.Join(*gpopath, gpoguid[0])
				}
				ui.Info().Msgf("Collecting group policy files from %v ...", gppath)

				_, err := os.Stat(gppath)
				if err != nil {
					ui.Warn().Msg("Can't access path, aborting this GPO ...")
				} else {
					gpoinfo := activedirectory.GPOdump{
						Common: basedata.GetCommonData(),
					}

					gpuuid, _ := uuid.FromString(gpoguid[0])

					gpoinfo.GPOinfo.GUID = gpuuid
					gpoinfo.GPOinfo.Path = originalpath // The original path is kept, we don't care
					gpoinfo.GPOinfo.DomainDN = domainContext
					gpoinfo.GPOinfo.DomainNetbios = netbiosname

					offset := len(gppath)
					var filescollected int
					filepath.WalkDir(gppath, func(curpath string, d fs.DirEntry, err error) error {
						if !d.IsDir() &&
							(strings.HasSuffix(strings.ToLower(curpath), ".adm") || strings.HasSuffix(strings.ToLower(curpath), ".admx")) {
							// Skip .adm(x) files that slipped in here
							return nil
						}

						var fileinfo activedirectory.GPOfileinfo
						fileinfo.IsDir = d.IsDir()
						if !fileinfo.IsDir {
							if info, err := d.Info(); err == nil {
								fileinfo.Timestamp = info.ModTime()
								fileinfo.Size = info.Size()
							}
						}
						fileinfo.RelativePath = curpath[offset:]

						if gppath == originalpath {
							// Do file ACL analysis if we're reading directly from SYSVOL
							owner, dacl, err := windowssecurity.GetOwnerAndDACL(curpath, windowssecurity.SE_FILE_OBJECT)
							if err == nil {
								fileinfo.OwnerSID = owner
								fileinfo.DACL = dacl
							} else {
								ui.Warn().Msgf("Problem getting %v DACL: %v", curpath, err)
							}
						}
						if !d.IsDir() {
							filescollected++

							rawfile, err := ioutil.ReadFile(curpath)
							if err == nil {
								fileinfo.Contents = rawfile
							} else {
								ui.Warn().Msgf("Problem getting %v contents: %v", curpath, err)
							}
						}
						gpoinfo.GPOinfo.Files = append(gpoinfo.GPOinfo.Files, fileinfo)
						return nil
					})

					if filescollected == 0 {
						ui.Warn().Msgf("No files found/accessible in %v", gppath)
					}

					gpodatafile := filepath.Join(datapath, gpoguid[0]+".gpodata.json")
					f, err := os.Create(gpodatafile)
					if err != nil {
						ui.Error().Msgf("Problem writing GPO information to %v: %v", gpodatafile, err)
						continue
					}
					defer f.Close()

					encoder := json.NewEncoder(f)
					encoder.SetIndent("", "  ")
					err = encoder.Encode(gpoinfo)
					if err != nil {
						ui.Error().Msgf("Problem marshalling GPO information to %v: %v", gpodatafile, err)
					}
				}
			} else {
				ui.Warn().Msgf("Skipping %v, not a GPO", object.Attributes["displayName"])
			}
		}
	}

	return nil
}
