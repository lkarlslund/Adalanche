package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Showmax/go-fqdn"
	"github.com/gofrs/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pierrec/lz4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/schollz/progressbar/v3"
	"github.com/tinylib/msgp/msgp"
	"golang.org/x/crypto/ssh/terminal"
)

// Install AssetFS compiler:
// go get github.com/go-bindata/go-bindata/...
// go get github.com/elazarl/go-bindata-assetfs/...

//go:generate go-bindata-assetfs html/... readme.MD

var (
	qjson = jsoniter.ConfigCompatibleWithStandardLibrary
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

	authmodeString := flag.String("authmode", "ntlmsspi", "Bind mode: unauth, simple, md5, ntlm, ntlmpth (password is hash), ntlmsspi (current user, default)")
	if runtime.GOOS != "windows" {
		// change default for non windows platofrms
		authmodeString = flag.String("authmode", "ntlm", "Bind mode: unauth, simple, md5, ntlm, ntlmpth (password is hash), ntlmsspi (current user, default)")
	}

	authdomain := flag.String("authdomain", "", "domain for authentication, if using ntlm auth")

	datapath := flag.String("datapath", "data", "folder to store cached ldap data")
	dumpquery := flag.String("dumpquery", "(objectClass=*)", "LDAP query for dump, defaults to everything")
	analyzequery := flag.String("analyzequery", "(&(objectClass=group)(|(name=Domain Admins)(name=Enterprise Admins)))", "LDAP query to locate targets for analysis")
	importall := flag.Bool("importall", false, "Load all attributes from dump (expands search options, but at the cost of memory")
	exportinverted := flag.Bool("exportinverted", false, "Invert analysis, discover how much damage targets can do")
	exporttype := flag.String("exporttype", "cytoscapejs", "Graph type to export (cytoscapejs, graphviz)")
	attributesparam := flag.String("attributes", "", "Comma seperated list of attributes to get, blank means everything")
	debuglogging := flag.Bool("debug", false, "Enable debug logging")
	nosacl := flag.Bool("nosacl", true, "Request data with NO SACL flag, allows normal users to dump ntSecurityDescriptor field")
	pagesize := flag.Int("pagesize", 1000, "Chunk requests into pages of this count of objects")
	bind := flag.String("bind", "127.0.0.1:8080", "Address and port of webservice to bind to")
	nobrowser := flag.Bool("nobrowser", false, "Don't launch browser after starting webservice")

	flag.Parse()

	if !*debuglogging {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		log.Debug().Msg("Debug logging enabled")
	}

	log.Info().Msg("adalanche (c) 2020-2021 Lars Karlslund, released under GPLv3, This program comes with ABSOLUTELY NO WARRANTY")

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
			log.Error().Msgf("Unknown LDAP authentication mode %v", *authmodeString)
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
				passwd, err := terminal.ReadPassword(int(syscall.Stdin))
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
		boutfile.Header.CompressionLevel = 10
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
		log.Debug().Msgf("Saving %v AD objects ...", len(rawobjects))
		for _, object := range rawobjects {

			// Let's check if it this is a GPO and then add a fake attribute if it affects local groups
			// if object.Attributes[]

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
		}

		cachefile, err := os.Open(filepath.Join(*datapath, domain+".objects.lz4.msgp"))
		if err != nil {
			log.Fatal().Msgf("Problem opening domain cache file: %v", err)
		}
		bcachefile := lz4.NewReader(cachefile)

		cachestat, _ := cachefile.Stat()

		loadbar := progressbar.NewOptions(int(cachestat.Size()),
			progressbar.OptionSetDescription("Loading objects from "+domain+" ..."),
			progressbar.OptionShowBytes(true),
			progressbar.OptionThrottle(time.Second*1),
			progressbar.OptionOnCompletion(func() { fmt.Println() }),
		)

		d := msgp.NewReader(bcachefile)
		// d := msgp.NewReader(&progressbar.Reader{bcachefile, &loadbar})

		// Load all the stuff
		var lastpos int64
		for {
			var rawObject RawObject
			err = rawObject.DecodeMsg(d)

			pos, _ := cachefile.Seek(0, io.SeekCurrent)
			loadbar.Add(int(pos - lastpos))
			lastpos = pos

			if err == nil {
				newObject := rawObject.ToObject(*importall)
				AllObjects.Add(&newObject)
			} else if msgp.Cause(err) == io.EOF {
				break
			} else {
				log.Fatal().Msgf("Problem decoding object: %v", err)
			}
		}
		cachefile.Close()
		loadbar.Finish()
	}

	log.Debug().Msgf("Loaded %v ojects", len(AllObjects.AsArray()))

	// Add our known SIDs if they're missing
	for sid, name := range knownsids {
		binsid, err := SIDFromString(sid)
		if err != nil {
			log.Fatal().Msgf("Problem parsing SID %v", sid)
		}
		if _, found := AllObjects.FindSID(binsid); !found {
			dn := "CN=" + name + ",CN=microsoft-builtin"
			log.Info().Msgf("Adding missing well known SID %v (%v) as %v", name, sid, dn)
			AllObjects.Add(&Object{
				DistinguishedName: dn,
				Attributes: map[Attribute][]string{
					Name:           {name},
					ObjectSid:      {string(binsid)},
					ObjectClass:    {"person", "user", "top"},
					ObjectCategory: {"Group"},
				},
			})
		}
	}

	// ShowAttributePopularity()

	// Generate member of chains
	processbar := progressbar.NewOptions(int(len(AllObjects.dnmap)),
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

		object.SetAttr(MetaType, object.Type().String())
		if lastlogon, ok := object.AttrTimestamp(LastLogonTimestamp); ok {
			object.SetAttr(MetaLastLoginAge, strconv.Itoa(int(time.Since(lastlogon)/time.Hour)))
		}
		if passwordlastset, ok := object.AttrTimestamp(PwdLastSet); ok {
			object.SetAttr(MetaPasswordAge, strconv.Itoa(int(time.Since(passwordlastset)/time.Hour)))
		}
		if strings.Contains(strings.ToLower(object.OneAttr(OperatingSystem)), "linux") {
			object.SetAttr(MetaLinux, "1")
		}
		if strings.Contains(strings.ToLower(object.OneAttr(OperatingSystem)), "windows") {
			object.SetAttr(MetaWindows, "1")
		}
		if len(object.Attr(MSmcsAdmPwdExpirationTime)) > 0 {
			object.SetAttr(MetaLAPSInstalled, "1")
		}
		if uac, ok := object.AttrInt(UserAccountControl); ok {
			if uac&UAC_TRUSTED_FOR_DELEGATION != 0 {
				object.SetAttr(MetaUnconstrainedDelegation, "1")
			}
			if uac&UAC_TRUSTED_TO_AUTH_FOR_DELEGATION != 0 {
				object.SetAttr(MetaConstrainedDelegation, "1")
			}
			if uac&UAC_NOT_DELEGATED != 0 {
				log.Debug().Msgf("%v has can't be used as delegation", object.DN())
			}
			if uac&UAC_WORKSTATION_TRUST_ACCOUNT != 0 {
				object.SetAttr(MetaWorkstation, "1")
			}
			if uac&UAC_SERVER_TRUST_ACCOUNT != 0 {
				object.SetAttr(MetaServer, "1")
			}
			if uac&UAC_ACCOUNTDISABLE != 0 {
				object.SetAttr(MetaAccountDisabled, "1")
			}
			if uac&UAC_PASSWD_CANT_CHANGE != 0 {
				object.SetAttr(MetaPasswordCantChange, "1")
			}
			if uac&UAC_DONT_EXPIRE_PASSWORD != 0 {
				object.SetAttr(MetaPasswordNoExpire, "1")
			}
			if uac&UAC_PASSWD_NOTREQD != 0 {
				object.SetAttr(MetaPasswordNotRequired, "1")
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

		// Special types of Objects
		if object.HasAttrValue(ObjectClass, "controlAccessRight") {
			u, err := uuid.FromString(object.OneAttr(A("rightsGuid")))
			// log.Debug().Msgf("Adding right %v %v", u, object.OneAttr(DisplayName))
			if err == nil {
				AllRights[u] = object
			}
		} else if object.HasAttrValue(ObjectClass, "attributeSchema") {
			objectGUID, err := uuid.FromBytes([]byte(object.OneAttr(A("schemaIDGUID"))))
			objectGUID = SwapUUIDEndianess(objectGUID)
			// log.Debug().Msgf("Adding schema attribute %v %v", u, object.OneAttr(Name))
			if err == nil {
				AllSchemaAttributes[objectGUID] = object
				switch object.OneAttr(Name) {
				case "ms-Mcs-AdmPwd":
					log.Info().Msg("Detected LAPS schema extension, adding extra analyzer")
					PwnAnalyzers = append(PwnAnalyzers, PwnAnalyzer{
						Method: PwnReadLAPSPassword,
						ObjectAnalyzer: func(o *Object) []*Object {
							var results []*Object
							// Only for computers
							if o.Type() != ObjectTypeComputer {
								return results
							}
							// ... that has LAPS installed
							if len(o.Attr(MSmcsAdmPwdExpirationTime)) == 0 {
								return results
							}
							// Analyze ACL
							sd, err := o.SecurityDescriptor()
							if err != nil {
								return results
							}
							for _, acl := range sd.DACL.Entries {
								if acl.Type == ACETYPE_ACCESS_ALLOWED_OBJECT && acl.Mask&RIGHT_DS_READ_PROPERTY != 0 && acl.ObjectType == objectGUID {
									results = append(results, AllObjects.FindOrAddSID(acl.SID))
								}
							}
							return results
						},
					})
				}
			}
		} else if object.HasAttrValue(ObjectClass, "classSchema") {
			u, err := uuid.FromBytes([]byte(object.OneAttr(A("schemaIDGUID"))))
			u = SwapUUIDEndianess(u)
			// log.Debug().Msgf("Adding schema class %v %v", u, object.OneAttr(Name))
			if err == nil {
				AllSchemaClasses[u] = object
			}
		}
	}
	processbar.Finish()

	// This sucks in a very bad way, Objects really needs to be an AD object :-\
	ad := AD{
		Domain: *domain,
	}

	// Find dsHeuristics, this defines groups EXCLUDED From AdminSDHolder application

	// https://social.technet.microsoft.com/wiki/contents/articles/22331.adminsdholder-protected-groups-and-security-descriptor-propagator.aspx#What_is_a_protected_group

	var excluded string
	if ds, found := AllObjects.Find("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + ad.RootDn()); found {
		excluded = ds.OneAttr(DsHeuristics)
	}

	// Let's see if we can find the AdminSDHolder container
	if adminsdholder, found := AllObjects.Find("cn=AdminSDHolder,cn=System," + ad.RootDn()); found {
		// We found it - so we know it can theoretically "pwn" any object with AdminCount > 0
		PwnAnalyzers = append(PwnAnalyzers, MakeAdminSDHolderPwnanalyzerFunc(adminsdholder, excluded))
	}

	// Generate member of chains
	pwnbar := progressbar.NewOptions(int(len(AllObjects.dnmap)),
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
		// log.Info().Msg(object.String())
		for _, analyzer := range PwnAnalyzers {
			for _, pwnobject := range analyzer.ObjectAnalyzer(object) {
				if pwnobject == object || pwnobject.SID() == object.SID() { // SID check solves (some) dual-AD analysis problems
					// We don't care about self owns
					continue
				}

				// Ignore these, SELF = self own, Creator/Owner always has full rights
				if pwnobject.SID() == SelfSID || pwnobject.SID() == CreatorOwnerSID || pwnobject.SID() == SystemSID {
					continue
				}
				// log.Debug().Msgf("Detected that %v can pwn %v by %v", pwnobject.DN(), object.DN(), analyzer.Method)
				pwnobject.CanPwn = pwnobject.CanPwn.Set(object, analyzer.Method)
				object.PwnableBy = object.PwnableBy.Set(pwnobject, analyzer.Method)
				pwnlinks++
			}
		}
	}
	pwnbar.Finish()
	log.Debug().Msgf("Detected %v ways to pwn objects", pwnlinks)

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
		resultgraph := AnalyzeObjects(includeobjects, nil, PwnMethod(PwnAllMethods), mode, 99)

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

		srv := webservice(*bind)

		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal().Msgf("Problem launching webservice listener: %s", err)
			} else {
				quit <- true
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
