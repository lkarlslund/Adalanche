package main

import (
	"embed"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Showmax/go-fqdn"
	"github.com/gofrs/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pierrec/lz4/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/schollz/progressbar/v3"
	"github.com/tinylib/msgp/msgp"
	"golang.org/x/term"
)

//go:embed html/*
var embeddedassets embed.FS

var (
	lapsdetect uint64
	qjson      = jsoniter.ConfigCompatibleWithStandardLibrary
)

var (
	programname = "adalanche"
	builddate   = "unknown_date"
	commit      = "unknown_commit"
)

func showUsage() {
	log.Info().Msg("Usage: adalanche [-options ...] command")
	log.Info().Msg(`Commands are:`)
	log.Info().Msg(`  dump - to dump an AD into a compressed file`)
	log.Info().Msg(`  analyze - launches embedded webservice`)
	log.Info().Msg(`  dump-analyze - dumps an AD and launches embedded webservice`)
	log.Info().Msg(`  export - save analysis to graph files`)
	log.Info().Msg(`Options:`)

	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		name, usage := flag.UnquoteUsage(f)
		s := fmt.Sprintf("  -%s", f.Name) // Two spaces before -; see next two comments.
		totallength := len(f.Name)
		if len(name) > 0 {
			s += " " + name
			totallength += 1 + len(name)
		}
		if totallength < 20 {
			s += strings.Repeat(" ", 20-totallength)
		}

		s += strings.ReplaceAll(usage, "\n", "\n                           ")

		if f.DefValue != "" {
			s += fmt.Sprintf(" (default %v)", f.DefValue)
		}

		log.Info().Msg(s)
	})

	os.Exit(0)
}

func main() {
	server := flag.String("server", "", "DC to connect to, use IP or full hostname ex. -dc=\"dc.contoso.local\", random DC is auto-detected if not supplied")
	port := flag.Int("port", 636, "LDAP port to connect to (389 or 636 typical)")
	domain := flag.String("domain", "", "domain suffix to analyze (auto-detected if not supplied)")
	user := flag.String("username", "", "username to connect with ex. -username=\"someuser\"")
	pass := flag.String("password", "", "password to connect with ex. -password=\"testpass!\"")

	tlsmode := flag.String("tlsmode", "TLS", "Transport mode (TLS, StartTLS, NoTLS)")

	ignoreCert := flag.Bool("ignorecert", true, "Disable certificate checks")

	defaultmode := "ntlm"
	if runtime.GOOS == "windows" {
		defaultmode = "ntlmsspi"
	}
	authmodeString := flag.String("authmode", defaultmode, "Bind mode: unauth, simple, md5, ntlm, ntlmpth (password is hash), ntlmsspi (current user, default)")

	authdomain := flag.String("authdomain", "", "domain for authentication, if using ntlm auth")

	datapath := flag.String("datapath", "data", "folder to store cached ldap data")
	dumpquery := flag.String("dumpquery", "(objectClass=*)", "LDAP query for dump, defaults to everything")
	analyzequery := flag.String("analyzequery", "(&(objectClass=group)(|(name=Domain Admins)(name=Enterprise Admins)))", "LDAP query to locate targets for analysis")
	importall := flag.Bool("importall", false, "Load all attributes from dump (expands search options, but at the cost of memory")

	exportinverted := flag.Bool("exportinverted", false, "Invert analysis, discover how much damage targets can do")
	exporttype := flag.String("exporttype", "cytoscapejs", "Graph type to export (cytoscapejs, graphviz)")
	attributesparam := flag.String("attributes", "", "Comma seperated list of attributes to get, blank means everything")

	debuglogging := flag.Bool("debug", false, "Enable debug logging")
	cpuprofile := flag.Bool("cpuprofile", false, "Save CPU profile from start to end of processing in datapath")

	nosacl := flag.Bool("nosacl", true, "Request data with NO SACL flag, allows normal users to dump ntSecurityDescriptor field")
	pagesize := flag.Int("pagesize", 1000, "Chunk requests into pages of this count of objects")
	bind := flag.String("bind", "127.0.0.1:8080", "Address and port of webservice to bind to")
	nobrowser := flag.Bool("nobrowser", false, "Don't launch browser after starting webservice")

	dumpgpos := flag.Bool("dumpgpos", false, "When dumping, do you want to include GPO file contents?")
	gpopath := flag.String("gpopath", "", "Override path to GPOs, useful for non Windows OS'es with mounted drive (/mnt/policies/ or similar)")

	collectorpath := flag.String("collectorpath", "collectordata", "Path to where collector JSON files are located")

	flag.Parse()

	if *cpuprofile {
		pproffile := filepath.Join(*datapath, "adalanche-cpuprofile-"+time.Now().Format("06010215040506")+".pprof")
		f, err := os.Create(pproffile)
		if err != nil {
			log.Fatal().Msgf("Could not set up CPU profiling in file %v: %v", pproffile, err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if !*debuglogging {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Debug logging enabled")
	}

	// We do lots of allocations when importing stuff, so lets set this aggressively
	debug.SetGCPercent(10)

	log.Info().Msgf("%v built %v commit %v", programname, builddate, commit)
	log.Info().Msg("(c) 2020-2021 Lars Karlslund, released under GPLv3, This program comes with ABSOLUTELY NO WARRANTY")

	// Ensure the cache folder is available
	if _, err := os.Stat(*datapath); os.IsNotExist(err) {
		err = os.Mkdir(*datapath, 0600)
		if err != nil {
			log.Fatal().Msgf("Could not create cache folder %v: %v", datapath, err)
		}
	}

	command := "dump-analyze"

	if flag.NArg() < 1 {
		log.Info().Msg("No command issued, assuming 'dump-analyze'. Try command 'help' to get help.")
	} else {
		command = flag.Arg(0)
	}

	// Auto detect domain if not supplied
	if *domain == "" {
		log.Info().Msg("No domain supplied, auto-detecting")
		*domain = strings.ToLower(os.Getenv("USERDNSDOMAIN"))
		if *domain == "" {
			// That didn't work, lets try something else
			f, err := fqdn.FqdnHostname()
			if err == nil {
				*domain = strings.ToLower(f[strings.Index(f, ".")+1:])
			}
		}
		if *domain == "" {
			log.Fatal().Msg("Domain auto-detection failed")
		} else {
			log.Info().Msgf("Auto-detected domain as %v", *domain)
		}
	}

	// Dump data?
	if command == "dump" || command == "dump-analyze" {
		if *domain != "" && *server == "" {
			// Auto-detect server
			cname, servers, err := net.LookupSRV("", "", "_ldap._tcp.dc._msdcs."+*domain)
			if err == nil && cname != "" && len(servers) != 0 {
				*server = servers[0].Target
				log.Info().Msgf("AD controller detected as: %v", *server)
			} else {
				log.Warn().Msg("AD controller auto-detection failed, use -server xxxx parameter")
			}
		}

		var authmode byte
		switch *authmodeString {
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
			log.Error().Msgf("Unknown LDAP authentication mode %v", authmodeString)
			showUsage()
		}

		if len(*domain) == 0 {
			log.Warn().Msg("Missing domain name  - please provider this on commandline")
			showUsage()
		}

		if len(*server) == 0 {
			log.Warn().Msg("Missing AD controller server name - please provider this on commandline")
			showUsage()
		}

		var username string
		if authmode != 5 {
			if *user == "" {
				// Auto-detect user
				*user = os.Getenv("USERNAME")
				if *user != "" {
					log.Info().Msgf("Auto-detected username as %v", *user)
				}
			}

			if *user == "" {
				log.Warn().Msg("Missing username - please provider this on commandline")
				showUsage()
			}

			if *pass == "" {
				fmt.Printf("Please enter password for %v: ", *user)
				passwd, err := term.ReadPassword(int(syscall.Stdin))
				fmt.Println()
				if err == nil {
					*pass = string(passwd)
				}
			}
			username = *user + "@" + *domain
		} else {
			log.Info().Msg("Using integrated NTLM authentication")
		}

		tlsm, err := TLSmodeString(*tlsmode)
		if err != nil {
			log.Warn().Msgf("Unknown TLS mode %v", *tlsmode)
			showUsage()
		}

		ad := AD{
			Domain:     *domain,
			Server:     *server,
			Port:       uint16(*port),
			User:       username,
			Password:   *pass,
			AuthDomain: *authdomain,
			TLSMode:    tlsm,
			IgnoreCert: *ignoreCert,
		}

		err = ad.Connect(authmode)
		if err != nil {
			log.Fatal().Msgf("Problem connecting to AD: %v", err)
		}

		var attributes []string
		if *attributesparam != "" {
			attributes = strings.Split(*attributesparam, ",")
		}

		outfile, err := os.Create(filepath.Join(*datapath, *domain+".objects.lz4.msgp"))
		if err != nil {
			log.Fatal().Msgf("Problem opening domain cache file: %v", err)
		}
		boutfile := lz4.NewWriter(outfile)
		lz4options := []lz4.Option{
			lz4.BlockChecksumOption(true),
			// lz4.BlockSizeOption(lz4.BlockSize(512 * 1024)),
			lz4.ChecksumOption(true),
			lz4.CompressionLevelOption(lz4.Level9),
			lz4.ConcurrencyOption(-1),
		}
		boutfile.Apply(lz4options...)
		e := msgp.NewWriter(boutfile)

		dumpbar := progressbar.NewOptions(0,
			progressbar.OptionSetDescription("Dumping..."),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSetItsString("objects"),
			progressbar.OptionOnCompletion(func() { fmt.Println() }),
			progressbar.OptionThrottle(time.Second*1),
		)

		log.Info().Msg("Dumping schema objects ...")
		rawobjects, err := ad.Dump("CN=Schema,CN=Configuration,"+ad.RootDn(), *dumpquery, attributes, *nosacl, *pagesize)
		if err != nil {
			log.Fatal().Msgf("Problem dumping AD: %v", err)
		}
		log.Debug().Msgf("Saving %v schema objects ...", len(rawobjects))
		for _, object := range rawobjects {
			err = object.EncodeMsg(e)
			if err != nil {
				log.Fatal().Msgf("Problem encoding LDAP object %v: %v", object.DistinguishedName, err)
			}
			dumpbar.Add(1)
		}

		log.Info().Msg("Dumping configuration objects ...")
		rawobjects, err = ad.Dump("CN=Configuration,"+ad.RootDn(), *dumpquery, attributes, *nosacl, *pagesize)
		if err != nil {
			log.Fatal().Msgf("Problem dumping AD: %v", err)
		}
		log.Debug().Msgf("Saving %v configuration objects ...", len(rawobjects))
		for _, object := range rawobjects {
			err = object.EncodeMsg(e)
			if err != nil {
				log.Fatal().Msgf("Problem encoding LDAP object %v: %v", object.DistinguishedName, err)
			}
			dumpbar.Add(1)
		}

		log.Info().Msg("Dumping forest DNS objects ...")
		rawobjects, err = ad.Dump("DC=ForestDnsZones,"+ad.RootDn(), *dumpquery, attributes, *nosacl, *pagesize)
		if err != nil {
			log.Warn().Msgf("Problem dumping forest DNS zones (maybe it doesn't exist): %v", err)
		} else {
			log.Debug().Msgf("Saving %v forest DNS objects ...", len(rawobjects))
			for _, object := range rawobjects {
				err = object.EncodeMsg(e)
				if err != nil {
					log.Fatal().Msgf("Problem encoding LDAP object %v: %v", object.DistinguishedName, err)
				}
				dumpbar.Add(1)
			}
		}
		log.Info().Msg("Dumping domain DNS objects ...")
		rawobjects, err = ad.Dump("DC=DomainDnsZones,"+ad.RootDn(), *dumpquery, attributes, *nosacl, *pagesize)
		if err != nil {
			log.Warn().Msgf("Problem dumping domain DNS zones (maybe it doesn't exist): %v", err)
		} else {
			log.Debug().Msgf("Saving %v domain DNS objects ...", len(rawobjects))
			for _, object := range rawobjects {
				err = object.EncodeMsg(e)
				if err != nil {
					log.Fatal().Msgf("Problem encoding LDAP object %v: %v", object.DistinguishedName, err)
				}
				dumpbar.Add(1)
			}
		}

		log.Info().Msg("Dumping main AD objects ...")
		rawobjects, err = ad.Dump(ad.RootDn(), *dumpquery, attributes, *nosacl, *pagesize)
		if err != nil {
			log.Fatal().Msgf("Problem dumping AD: %v", err)
		}

		if *dumpgpos {
			log.Debug().Msg("Collecting GPO files ...")
			for _, object := range rawobjects {
				// Let's check if it this is a GPO and then add some fake attributes to represent it
				if gpfsp, found := object.Attributes["gPCFileSysPath"]; found {
					gpodisplayname := object.Attributes["displayName"]
					gpoguid := object.Attributes["name"]

					gppath := gpfsp[0]
					if *gpopath != "" {
						if len(gpoguid) != 1 {
							log.Warn().Msgf("GPO %v GUID not readable, skipping", gpodisplayname)
							continue
						}
						// Override path, possibly on other OS'es or if you dont have DNS running
						// gppath = *gpopath
						// gppath = strings.ReplaceAll(gppath, "%SERVER%", *server)
						// gppath = strings.ReplaceAll(gppath, "%DOMAIN%", *domain)
						// gppath = strings.ReplaceAll(gppath, "%GUID%", gpoguid[0])
						gppath = filepath.Join(*gpopath, gpoguid[0])
					}
					log.Info().Msgf("Dumping group policy files from %v ...", gppath)
					_, err := os.Stat(gppath)
					if err != nil {
						log.Warn().Msg("Can't access path, aborting this GPO ...")
					} else {
						offset := len(gppath)
						filepath.WalkDir(gppath, func(curpath string, d fs.DirEntry, err error) error {
							if !d.IsDir() {
								rawfile, err := ioutil.ReadFile(curpath)
								if err == nil {
									subpath := curpath[offset:]
									object.Attributes[path.Join("_gpofile", strings.TrimPrefix(strings.ReplaceAll(subpath, "\\", "/"), "/"))] = []string{string(rawfile)}
								}
							}
							return nil
						})

					}
				}
			}
		}

		log.Debug().Msgf("Saving %v AD objects ...", len(rawobjects))
		for _, object := range rawobjects {
			err = object.EncodeMsg(e)
			if err != nil {
				log.Fatal().Msgf("Problem encoding LDAP object %v: %v", object.DistinguishedName, err)
			}
			dumpbar.Add(1)
		}
		dumpbar.Finish()

		err = ad.Disconnect()
		if err != nil {
			log.Fatal().Msgf("Problem disconnecting from AD: %v", err)
		}

		e.Flush()
		boutfile.Close()
		outfile.Close()

	}

	if command == "dump" {
		os.Exit(0)
	}

	// Everything else requires us to load data
	if len(*domain) == 0 {
		log.Error().Msg("Please provide domain name")
		showUsage()
	}

	for _, domain := range strings.Split(*domain, ",") {
		if AllObjects.Base == "" { // Shoot me, this is horrible
			AllObjects.Base = "dc=" + strings.Replace(domain, ".", ",dc=", -1)
			AllObjects.Domain = domain
			domainparts := strings.Split(domain, ".") // From bad to worse FIXME
			AllObjects.DomainNetbios = strings.ToUpper(domainparts[0])
		}

		cachefile, err := os.Open(filepath.Join(*datapath, domain+".objects.lz4.msgp"))
		if err != nil {
			log.Fatal().Msgf("Problem opening domain cache file: %v", err)
		}
		bcachefile := lz4.NewReader(cachefile)

		lz4options := []lz4.Option{lz4.ConcurrencyOption(-1)}
		bcachefile.Apply(lz4options...)

		d := msgp.NewReaderSize(bcachefile, 4*1024*1024)

		objectstoadd := make(chan *RawObject, 8192)
		var importmutex sync.Mutex
		var done sync.WaitGroup
		for i := 0; i < runtime.NumCPU(); i++ {
			done.Add(1)
			go func() {
				chunk := make([]*Object, 0, 64)
				for addme := range objectstoadd {
					o := addme.ToObject(*importall)

					// Here's a quirky workaround that will bite me later
					// Legacy well known objects in ForeignSecurityPrincipals gives us trouble with duplicate SIDs - skip them
					if strings.Count(o.OneAttrString(ObjectSid), "-") == 3 && strings.Contains(o.OneAttrString(DistinguishedName), "CN=ForeignSecurityPrincipals") {
						continue
					}

					chunk = append(chunk, o)
					if cap(chunk) == len(chunk) {
						// Send chunk to objects
						importmutex.Lock()
						AllObjects.Add(chunk...)
						importmutex.Unlock()
						chunk = chunk[:0]
					}
				}
				// Process the last incomplete chunk
				importmutex.Lock()
				AllObjects.Add(chunk...)
				importmutex.Unlock()
				done.Done()
			}()
		}

		cachestat, _ := cachefile.Stat()

		loadbar := progressbar.NewOptions(int(cachestat.Size()),
			progressbar.OptionSetDescription("Loading objects from "+domain+" ..."),
			progressbar.OptionShowBytes(true),
			progressbar.OptionThrottle(time.Second*1),
			progressbar.OptionOnCompletion(func() { fmt.Println() }),
		)

		// d := msgp.NewReader(&progressbar.Reader{bcachefile, &loadbar})

		// Load all the stuff
		var lastpos int64
		// justread := make([]byte, 4*1024*1024)
		var iteration uint32
		for {
			iteration++
			if iteration%1000 == 0 {
				pos, _ := cachefile.Seek(0, io.SeekCurrent)
				loadbar.Add(int(pos - lastpos))
				lastpos = pos
			}

			var rawObject RawObject
			err = rawObject.DecodeMsg(d)
			if err == nil {
				objectstoadd <- &rawObject
			} else if msgp.Cause(err) == io.EOF {
				close(objectstoadd)
				done.Wait()
				break
			} else {
				log.Fatal().Msgf("Problem decoding object: %v", err)
			}
		}
		cachefile.Close()
		loadbar.Finish()
	}

	log.Info().Msgf("Loaded %v ojects", len(AllObjects.AsArray()))

	var statarray []string
	for stat, count := range AllObjects.Statistics() {
		if stat == 0 {
			continue
		}
		statarray = append(statarray, fmt.Sprintf("%v: %v", ObjectType(stat).String(), count))
	}
	log.Info().Msg(strings.Join(statarray, ", "))

	// Add our known SIDs if they're missing
	for sid, name := range knownsids {
		binsid, err := SIDFromString(sid)
		if err != nil {
			log.Fatal().Msgf("Problem parsing SID %v", sid)
		}
		if _, found := AllObjects.Find(ObjectSid, AttributeValueSID(binsid)); !found {
			dn := "CN=" + name + ",CN=microsoft-builtin"
			log.Info().Msgf("Adding missing well known SID %v (%v) as %v", name, sid, dn)
			AllObjects.Add(NewObject(
				DistinguishedName, AttributeValueString(dn),
				Name, AttributeValueString(name),
				ObjectSid, AttributeValueSID(binsid),
				ObjectClass, AttributeValueString("person"), AttributeValueString("user"), AttributeValueString("top"),
				ObjectCategory, AttributeValueString("Group"),
			))
		}
	}

	// Import collector JSON files
	if *collectorpath != "" {
		if st, err := os.Stat(*collectorpath); err == nil && st.IsDir() {
			log.Info().Msgf("Scanning for collector files from %v ...", *collectorpath)
			var jsonfiles []string
			filepath.Walk(*collectorpath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
					jsonfiles = append(jsonfiles, path)
				}
				return nil
			})

			importcollectorbar := progressbar.NewOptions(len(jsonfiles),
				progressbar.OptionSetDescription("Importing externally collected machine data ..."),
				progressbar.OptionShowCount(),
				progressbar.OptionShowIts(),
				progressbar.OptionSetItsString("JSON files"),
				progressbar.OptionOnCompletion(func() { fmt.Println() }),
				progressbar.OptionThrottle(time.Second*1),
			)
			for _, path := range jsonfiles {
				err = importCollectorFile(path, &AllObjects)
				if err != nil {
					log.Warn().Msgf("Problem processing collector file %v: %v", path, err)
				}
				importcollectorbar.Add(1)
			}
			importcollectorbar.Finish()
		} else {
			log.Warn().Msgf("Not importing collector files, path %v not accessible", *collectorpath)
		}
	}

	// Generate member of chains
	processbar := progressbar.NewOptions(int(len(AllObjects.AsArray())),
		progressbar.OptionSetDescription("Processing objects..."),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("objects"),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
		progressbar.OptionThrottle(time.Second*1),
	)

	// everyonesid, _ := SIDFromString("S-1-1-0")
	// everyone, ok := AllObjects.FindSID(everyonesid)
	// if !ok {
	// 	log.Fatal().Msgf("Could not locate Everyone, aborting")
	// }

	// authenticateduserssid, _ := SIDFromString("S-1-5-11")
	// authenticatedusers, ok := AllObjects.FindSID(authenticateduserssid)
	// if !ok {
	// 	log.Fatal().Msgf("Could not locate Authenticated Users, aborting")
	// }

	log.Info().Msg("Pre-processing directory data ...")
	for _, object := range AllObjects.AsArray() {
		processbar.Add(1)
		object.MemberOf()

		// Crude special handling for Everyone and Authenticated Users
		// if object.Type() == ObjectTypeUser || object.Type() == ObjectTypeComputer || object.Type() == ObjectTypeManagedServiceAccount {
		// 	everyone.imamemberofyou(object)
		// 	authenticatedusers.imamemberofyou(object)
		// 	object.memberof = append(object.memberof, everyone, authenticatedusers)
		// }

		if lastlogon, ok := object.AttrTimestamp(LastLogonTimestamp); ok {
			object.SetAttr(MetaLastLoginAge, AttributeValueInt(int(time.Since(lastlogon)/time.Hour)))
		}
		if passwordlastset, ok := object.AttrTimestamp(PwdLastSet); ok {
			object.SetAttr(MetaPasswordAge, AttributeValueInt(int(time.Since(passwordlastset)/time.Hour)))
		}
		if strings.Contains(strings.ToLower(object.OneAttrString(OperatingSystem)), "linux") {
			object.SetAttr(MetaLinux, AttributeValueInt(1))
		}
		if strings.Contains(strings.ToLower(object.OneAttrString(OperatingSystem)), "windows") {
			object.SetAttr(MetaWindows, AttributeValueInt(1))
		}
		if object.Attr(MSmcsAdmPwdExpirationTime).Len() > 0 {
			object.SetAttr(MetaLAPSInstalled, AttributeValueInt(1))
		}
		if uac, ok := object.AttrInt(UserAccountControl); ok {
			if uac&UAC_TRUSTED_FOR_DELEGATION != 0 {
				object.SetAttr(MetaUnconstrainedDelegation, AttributeValueInt(1))
			}
			if uac&UAC_TRUSTED_TO_AUTH_FOR_DELEGATION != 0 {
				object.SetAttr(MetaConstrainedDelegation, AttributeValueInt(1))
			}
			if uac&UAC_NOT_DELEGATED != 0 {
				log.Debug().Msgf("%v has can't be used as delegation", object.DN())
			}
			if uac&UAC_WORKSTATION_TRUST_ACCOUNT != 0 {
				object.SetAttr(MetaWorkstation, AttributeValueInt(1))
			}
			if uac&UAC_SERVER_TRUST_ACCOUNT != 0 {
				object.SetAttr(MetaServer, AttributeValueInt(1))
			}
			if uac&UAC_ACCOUNTDISABLE != 0 {
				object.SetAttr(MetaAccountDisabled, AttributeValueInt(1))
			}
			if uac&UAC_PASSWD_CANT_CHANGE != 0 {
				object.SetAttr(MetaPasswordCantChange, AttributeValueInt(1))
			}
			if uac&UAC_DONT_EXPIRE_PASSWORD != 0 {
				object.SetAttr(MetaPasswordNoExpire, AttributeValueInt(1))
			}
			if uac&UAC_PASSWD_NOTREQD != 0 {
				object.SetAttr(MetaPasswordNotRequired, AttributeValueInt(1))
			}
		}

		if object.Type() == ObjectTypeTrust {
			// http://www.frickelsoft.net/blog/?p=211
			var direction string
			dir, _ := object.AttrInt(TrustDirection)
			switch dir {
			case 0:
				direction = "disabled"
			case 1:
				direction = "incoming"
			case 2:
				direction = "outgoing"
			case 3:
				direction = "bidirectional"
			}

			attr, _ := object.AttrInt(TrustAttributes)
			log.Debug().Msgf("Domain has a %v trust with %v", direction, object.OneAttr(TrustPartner))
			if dir&2 != 0 && attr&4 != 0 {
				log.Debug().Msgf("SID filtering is not enabled, so pwn %v and pwn this AD too", object.OneAttr(TrustPartner))
			}
		}

		/*
			// Add DA EA AD to Hackers Won
			switch object.Type() {
			case ObjectTypeGroup:
				switch object.OneAttr(Name) {
				case "Domain Admins", "Enterprise Admins", "Administrators":
					HackersWonObject.CanPwn.Set(object, PwnMemberOfGroup)
					object.PwnableBy.Set(HackersWonObject, PwnMemberOfGroup)
				}
			case ObjectTypeCertificateTemplate:
				if nf, ok := object.AttrInt(MSPKICertificateNameFlag); nf&1 == 1 && ok {
					// Template that users can supply SAN to - can it be abused to do Client Auth?
					var clientauth bool

					// No usage == client auth, so says SpectreOps
					if len(object.Attr(PKIExtendedUsage)) == 0 {
						clientauth = true
					}

					for _, eu := range object.Attr(PKIExtendedUsage) {
						switch eu {
						case "1.3.6.1.5.5.7.3.2", "1.3.5.1.5.2.3.4", "1.3.6.1.4.1.311.20.2.2", "2.5.29.37.0":
							clientauth = true
						}
					}

					if clientauth {
						HackersWonObject.CanPwn.Set(object, PwnMemberOfGroup)
						object.PwnableBy.Set(HackersWonObject, PwnMemberOfGroup)
					}
				}
			}
		*/

		// Special types of Objects

		if object.HasAttrValue(ObjectClass, "controlAccessRight") {
			if u, ok := object.OneAttrRaw(RightsGUID).(uuid.UUID); ok {
				AllRights[u] = object
			}
		} else if object.HasAttrValue(ObjectClass, "attributeSchema") {
			if objectGUID, ok := object.OneAttrRaw(SchemaIDGUID).(uuid.UUID); ok {

				AllSchemaAttributes[objectGUID] = object
				switch object.OneAttrString(Name) {
				case "ms-Mcs-AdmPwd":
					log.Info().Msg("Detected LAPS schema extension, adding extra analyzer")
					PwnAnalyzers = append(PwnAnalyzers, PwnAnalyzer{
						Method: PwnReadLAPSPassword,
						ObjectAnalyzer: func(o *Object) {
							// Only for computers
							if o.Type() != ObjectTypeComputer {
								return
							}
							// ... that has LAPS installed
							if o.Attr(MSmcsAdmPwdExpirationTime).Len() == 0 {
								return
							}
							// Analyze ACL
							sd, err := o.SecurityDescriptor()
							if err != nil {
								return
							}
							for index, acl := range sd.DACL.Entries {
								if sd.DACL.AllowObjectClass(index, o, RIGHT_DS_CONTROL_ACCESS, objectGUID) {
									lapsdetect++
									AllObjects.FindOrAddSID(acl.SID).Pwns(o, PwnReadLAPSPassword, 100)
								}
							}
						},
					})
				}
			}
		} else if object.HasAttrValue(ObjectClass, "classSchema") {
			if u, ok := object.OneAttrRaw(SchemaIDGUID).(uuid.UUID); ok {
				// log.Debug().Msgf("Adding schema class %v %v", u, object.OneAttr(Name))
				AllSchemaClasses[u] = object
			}
		}
	}
	processbar.Finish()

	// This sucks in a very bad way, Objects really needs to be an AD object :-\
	ad := AD{
		Domain: *domain,
	}

	// Let's see if we can find the AdminSDHolder container
	if adminsdholder, found := AllObjects.Find(DistinguishedName, AttributeValueString("CN=AdminSDHolder,CN=System,"+ad.RootDn())); found {
		// We found it - so we know it can theoretically "pwn" some objects, lets see if some are excluded though
		excluded_mask := 0
		// Find dsHeuristics, this defines groups EXCLUDED From AdminSDHolder application
		// https://social.technet.microsoft.com/wiki/contents/articles/22331.adminsdholder-protected-groups-and-security-descriptor-propagator.aspx#What_is_a_protected_group
		if ds, found := AllObjects.Find(DistinguishedName, AttributeValueString("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,"+ad.RootDn())); found {
			excluded := ds.OneAttrString(DsHeuristics)
			if len(excluded) >= 16 {
				excluded_mask = strings.Index("0123456789ABCDEF", string(excluded[15]))
			}
		}

		PwnAnalyzers = append(PwnAnalyzers, MakeAdminSDHolderPwnanalyzerFunc(adminsdholder, excluded_mask))
	}

	// Generate member of chains
	pwnbar := progressbar.NewOptions(int(len(AllObjects.AsArray())),
		progressbar.OptionSetDescription("Analyzing who can pwn who ..."),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("objects"),
		// progressbar.OptionShowBytes(true),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
		progressbar.OptionThrottle(time.Second*1),
	)

	var pwnlinks int
	for _, object := range AllObjects.AsArray() {
		pwnbar.Add(1)
		for _, analyzer := range PwnAnalyzers {
			analyzer.ObjectAnalyzer(object)
			pwnlinks++
		}
	}
	pwnbar.Finish()
	log.Info().Msgf("Detected %v ways to pwn objects", pwnlinks)

	var pwnarray []string
	for pwn, count := range pwnpopularity {
		if pwn == 0 {
			continue
		}
		pwnarray = append(pwnarray, fmt.Sprintf("%v: %v", PwnMethod(pwn).String(), count))
	}
	log.Info().Msg(strings.Join(pwnarray, ", "))

	log.Info().Msgf("LAPS detect: %v", lapsdetect)

	switch command {
	case "exportacls":
		log.Info().Msg("Finding most valuable assets ...")

		output, err := os.Create("debug.txt")
		if err != nil {
			log.Fatal().Msgf("Error opening output file: %v", err)
		}

		for _, object := range AllObjects.AsArray() {
			fmt.Fprintf(output, "Object:\n%v\n\n-----------------------------\n", object)
		}
		output.Close()

		log.Info().Msg("Done")
	case "export":
		log.Info().Msg("Finding most valuable assets ...")
		q, err := ParseQueryStrict(*analyzequery)
		if err != nil {
			log.Fatal().Msgf("Error parsing LDAP query: %v", err)
		}

		includeobjects := AllObjects.Filter(func(o *Object) bool {
			return q.Evaluate(o)
		})

		mode := "normal"
		if *exportinverted {
			mode = "inverted"
		}
		resultgraph := AnalyzeObjects(includeobjects, nil, AllPwnMethods, mode, 99, 0, 1)

		switch *exporttype {
		case "graphviz":
			err = ExportGraphViz(resultgraph, "adalanche-"+*domain+".dot")
		case "cytoscapejs":
			err = ExportCytoscapeJS(resultgraph, "adalanche-cytoscape-js-"+*domain+".json")
		default:
			log.Error().Msg("Unknown export format")
			showUsage()
		}
		if err != nil {
			log.Fatal().Msgf("Problem exporting graph: %v", err)
		}

		log.Info().Msg("Done")
	case "analyze", "dump-analyze":
		quit := make(chan bool)

		srv := webservice(*bind, quit)

		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal().Msgf("Problem launching webservice listener: %s", err)
			}
		}()

		// Launch browser
		if !*nobrowser {
			var err error
			url := "http://" + *bind
			switch runtime.GOOS {
			case "linux":
				err = exec.Command("xdg-open", url).Start()
			case "windows":
				err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
			case "darwin":
				err = exec.Command("open", url).Start()
			default:
				err = fmt.Errorf("unsupported platform")
			}
			if err != nil {
				log.Debug().Msgf("Problem launching browser: %v", err)
			}
		}

		// Wait for webservice to end
		<-quit
	default:
		log.Error().Msgf("Unknown command %v", flag.Arg(0))
		showUsage()
	}
}
