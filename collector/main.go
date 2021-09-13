package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	winio "github.com/Microsoft/go-winio"
	"github.com/antchfx/xmlquery"
	"github.com/gravwell/gravwell/v3/winevent"
	"github.com/lkarlslund/adalanche/modules/collector"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	winapi "github.com/lkarlslund/go-win64api"
	"github.com/mattn/go-colorable"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	programname = "adalanche-collector"
	builddate   = "unknown_date"
	commit      = "unknown_commit"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: colorable.NewColorableStdout()})

	log.Info().Msgf("%v built %v commit %v", programname, builddate, commit)
	log.Info().Msg("(c) 2020-2021 Lars Karlslund, released under GPLv3, This program comes with ABSOLUTELY NO WARRANTY")

	// MACHINE
	hostname, _ := os.Hostname()
	hostsid, _ := winio.LookupSidByName(hostname)

	var domain *uint16
	var status uint32
	syscall.NetGetJoinInformation(nil, &domain, &status)
	defer syscall.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))

	numcpus, _ := strconv.Atoi(os.Getenv(`NUMBER_OF_PROCESSORS`))

	isdomainjoined := status == syscall.NetSetupDomainName
	var hostdomainsid string
	if isdomainjoined {
		hostdomainsid, _ = winio.LookupSidByName(hostname + "$")
	}

	machineinfo := collector.Machine{
		Name:               hostname,
		LocalSID:           hostsid,
		Domain:             winapi.UTF16toString(domain),
		IsDomainJoined:     isdomainjoined,
		ComputerDomainSID:  hostdomainsid,
		Architecture:       os.Getenv(`PROCESSOR_ARCHITECTURE`),
		NumberOfProcessors: numcpus,
	}

	currentversion_key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.READ|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err == nil {
		defer currentversion_key.Close()
		machineinfo.ProductName, _, _ = currentversion_key.GetStringValue("ProductName")
		machineinfo.EditionID, _, _ = currentversion_key.GetStringValue("EditionId")
		machineinfo.ReleaseID, _, _ = currentversion_key.GetStringValue("ReleaseId")
		machineinfo.BuildBranch, _, _ = currentversion_key.GetStringValue("BuildBranch")
		machineinfo.MajorVersionNumber, _, _ = currentversion_key.GetIntegerValue("CurrentVersionMajorNumber")
		machineinfo.Version, _, _ = currentversion_key.GetStringValue("CurrentVersion")
		machineinfo.BuildNumber, _, _ = currentversion_key.GetStringValue("CurrentBuildNumber")
		UBR, _, _ := currentversion_key.GetStringValue("UBR")
		if UBR != "" {
			machineinfo.BuildNumber += "." + UBR
		}
	}

	// AUTOLOGON - FREE CREDENTIALS
	winlogon_key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		registry.READ|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err == nil {
		defer winlogon_key.Close()
		pwd, _, _ := winlogon_key.GetStringValue(`DefaultPassword`)
		if pwd != "" {
			machineinfo.DefaultUsername, _, _ = winlogon_key.GetStringValue(`DefaultUsername`)
			machineinfo.DefaultDomain, _, _ = winlogon_key.GetStringValue(`DefaultDomain`)
		}
		pwd, _, _ = winlogon_key.GetStringValue(`AltDefaultPassword`)
		if pwd != "" {
			machineinfo.AltDefaultUsername, _, _ = winlogon_key.GetStringValue(`AltDefaultUsername`)
			machineinfo.AltDefaultDomain, _, _ = winlogon_key.GetStringValue(`AltDefaultDomain`)
		}
	}

	// APP COMPAT CACHE - LAST 1024 PROGRAM EXECUTIONS
	system_key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM`,
		registry.READ|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err == nil {
		defer system_key.Close()
		subnames, _ := system_key.ReadSubKeyNames(-1)
		for _, subkey := range subnames {
			appcache_key, err := registry.OpenKey(system_key, subkey+`\Control\Session Manager\AppCompatCache`,
				registry.READ|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
			if err == nil {
				defer appcache_key.Close()
				cache, _, err := appcache_key.GetBinaryValue(`AppCompatCache`)
				if err == nil {
					// Export data
					machineinfo.AppCache = append(machineinfo.AppCache, cache)
				}
			}
		}
	}

	// SCCM SETTINGS
	ccmsetup_key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\CCMSetup`,
		registry.READ|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err == nil {
		defer ccmsetup_key.Close()
		machineinfo.SCCMLastValidMP, _, _ = ccmsetup_key.GetStringValue(`LastValidMP`)
	}

	// UAC SETTINGS
	polsys_key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Policies\System`,
		registry.READ|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err == nil {
		defer polsys_key.Close()
		machineinfo.UACConsentPromptBehaviorAdmin, _, _ = polsys_key.GetIntegerValue(`ConsentPromptBehaviorAdmin`)
		machineinfo.UACEnableLUA, _, _ = polsys_key.GetIntegerValue(`EnableLUA`)
		machineinfo.UACLocalAccountTokenFilterPolicy, _, _ = polsys_key.GetIntegerValue(`LocalAccountTokenFilterPolicy`)
		machineinfo.UACFilterAdministratorToken, _, _ = polsys_key.GetIntegerValue(`FilterAdministratorToken`)
	}

	// SHARES
	var sharesinfo collector.Shares

	shares_key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`,
		registry.READ|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err == nil {
		defer shares_key.Close()
		permissions_key, err := registry.OpenKey(shares_key,
			`Security`,
			registry.READ|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
		if err == nil {
			defer permissions_key.Close()

			shares, err := shares_key.ReadValueNames(-1)
			if err == nil {
				for _, share := range shares {
					permissions, _, _ := permissions_key.GetBinaryValue(share)
					shareinfo := collector.Share{
						Name: share,
						DACL: permissions,
					}

					share_settings, _, err := shares_key.GetStringsValue(share)
					if err == nil {
						for _, share_setting := range share_settings {
							ss := strings.Split(share_setting, "=")
							if len(ss) == 2 {
								switch ss[0] {
								case "Type":
									stype, _ := strconv.Atoi(ss[1])
									shareinfo.Type = stype
								case "ShareName":
									shareinfo.Name = ss[1]
								case "Remark":
									shareinfo.Remark = ss[1]
								case "Path":
									shareinfo.Path = ss[1]
								}
							}
						}
					}

					// if stype >= 16 {
					sharesinfo = append(sharesinfo, shareinfo)
					// }
				}
			}
		}
	}

	// GATHER INTERESTING STUFF FROM EVENT LOG

	// chn, _ := wineventlog.Channels()
	// for _, channel := range chn {
	// 	fmt.Println(channel)
	// }

	// Who has logged on and when https://nasbench.medium.com/finding-forensic-goodness-in-obscure-windows-event-logs-60e978ea45a3
	// Event 811 and 812 :-)
	monthmap := make(map[string]uint64)
	weekmap := make(map[string]uint64)
	daymap := make(map[string]uint64)

	elog, err := winevent.NewStream(winevent.EventStreamParams{
		Channel:  "Microsoft-Windows-Winlogon/Operational",
		EventIDs: "811,812",
		BuffSize: 2048000,
	}, 0)

	if err == nil {
		for {
			events, _, _, err := elog.Read()
			if err != nil {
				// fmt.Println(err)
				break
			}
			for _, event := range events {
				// fmt.Println(string(event.Buff))
				doc, err := xmlquery.Parse(bytes.NewReader(event.Buff))
				if err == nil {
					i := xmlquery.FindOne(doc, "//Event//System//EventID")
					if i.InnerText() == "811" {
						// Login
						user := xmlquery.FindOne(doc, "//Event//System//Security//@UserID")
						timestamp := xmlquery.FindOne(doc, "//Event//System//TimeCreated//@SystemTime")

						us := user.InnerText()
						t, _ := time.Parse(time.RFC3339Nano, timestamp.InnerText())
						if t.After(amonthago) {
							monthmap[us] = monthmap[us] + 1
						}
						if t.After(aweekago) {
							weekmap[us] = weekmap[us] + 1
						}
						if t.After(adayago) {
							daymap[us] = daymap[us] + 1
						}
						// fmt.Printf("%v logged in %v", user.InnerText(), timestamp.InnerText())
					}
				}
			}
		}
	}
	var logininfo collector.LoginPopularity
	for usersid, count := range monthmap {
		var name, domain string
		sid, err := syscall.StringToSid(usersid)
		if err == nil {
			name, domain, _, err = sid.LookupAccount("")
		}
		logininfo.Month = append(logininfo.Month, collector.LoginCount{
			Name:  domain + "\\" + name,
			SID:   usersid,
			Count: count,
		})
	}
	for usersid, count := range weekmap {
		var name, domain string
		sid, err := syscall.StringToSid(usersid)
		if err == nil {
			name, domain, _, err = sid.LookupAccount("")
		}
		logininfo.Week = append(logininfo.Week, collector.LoginCount{
			Name:  domain + "\\" + name,
			SID:   usersid,
			Count: count,
		})
	}
	for usersid, count := range daymap {
		var name, domain string
		sid, err := syscall.StringToSid(usersid)
		if err == nil {
			name, domain, _, err = sid.LookupAccount("")
		}
		logininfo.Day = append(logininfo.Day, collector.LoginCount{
			Name:  domain + "\\" + name,
			SID:   usersid,
			Count: count,
		})
	}

	// MACHINE AVAILABILITY
	var timeonmonth, timeonweek, timeonday time.Duration
	elog, err = winevent.NewStream(winevent.EventStreamParams{
		Channel: "System",
		Providers: []string{
			"Eventlog",
			"Microsoft-Windows-Kernel-General",
			"Microsoft-Windows-Power",
			"Microsoft-Windows-Power-Troubleshooter",
		},
		EventIDs: "1,12,13,42,6008",
		BuffSize: 2048000,
	}, 0)

	var availabilityinfo collector.Availability
	var laststart, laststop time.Time
	laststart = laststart.Add(time.Minute) // First hit in event log might be a shutdown event, so we just assume it was powered on ages ago
	if err == nil {
		for {
			events, _, _, err := elog.Read()
			if err != nil {
				// fmt.Println(err)
				break
			}
			for _, event := range events {
				doc, err := xmlquery.Parse(bytes.NewReader(event.Buff))
				if err == nil {
					providername := xmlquery.FindOne(doc, "//Event//System//Provider").SelectAttr("Name")
					eventid := xmlquery.FindOne(doc, "//Event//System//EventID").InnerText()

					timestamp := xmlquery.FindOne(doc, "//Event//System//TimeCreated//@SystemTime")
					t, err := time.Parse(time.RFC3339Nano, timestamp.InnerText())
					if err == nil {
						switch eventid {
						case "1": // Power on
							if providername == "Microsoft-Windows-Power-Troubleshooter" {
								eventdata := xmlquery.Find(doc, "//Event//EventData//Data")
								for _, event := range eventdata {
									if event.SelectAttr("Name") == "SleepTime" {
										st, err := time.Parse(time.RFC3339Nano, event.InnerText())
										if err == nil {
											laststop = st
											// Might be an interval ...
											if !laststart.IsZero() && !laststop.IsZero() && laststart.Before(laststop) {
												// log.Info().Msgf("%v -> %v", laststart, laststop)
												registertimes(laststart, laststop, &timeonmonth, &timeonweek, &timeonday)
												laststart = time.Time{}
												laststop = time.Time{}
											}
										}
									} else if event.SelectAttr("Name") == "WakeTime" {
										st, err := time.Parse(time.RFC3339Nano, event.InnerText())
										if err == nil {
											laststart = st
										}
									}
								}

								laststart = t
								// log.Info().Msgf("%v %v %v %v", t, providername, eventid, string(event.Buff))
								// log.Info().Msgf("%v %v %v", t, providername, eventid)
							}
						case "12": // Startup
							if providername == "Microsoft-Windows-Kernel-General" {
								laststart = t
								// log.Info().Msgf("%v %v %v", t, providername, eventid)
							}
						case "13": // Shutdown
							if providername == "Microsoft-Windows-Kernel-General" {
								laststop = t
								// log.Info().Msgf("%v %v %v", t, providername, eventid)
							}
						case "42": // Sleep
							if providername == "Microsoft-Windows-Kernel-Power" {
								laststop = t
								// log.Info().Msgf("%v %v %v %v", t, providername, eventid, string(event.Buff))
								// log.Info().Msgf("%v %v %v", t, providername, eventid)
							}
						case "6008": // Unexpected shutdown
							if providername == "Eventlog" {
								laststop = t
								// log.Info().Msgf("%v %v %v", t, providername, eventid)
							}
						}
					}

					if !laststart.IsZero() && !laststop.IsZero() && laststart.Before(laststop) {
						// log.Info().Msgf("%v -> %v", laststart, laststop)
						registertimes(laststart, laststop, &timeonmonth, &timeonweek, &timeonday)
						laststart = time.Time{}
						laststop = time.Time{}
					}
				}
			}

		}
		if !laststart.IsZero() && laststop.IsZero() {
			laststop = time.Now() // We're still running we assume ;-D
			registertimes(laststart, laststop, &timeonmonth, &timeonweek, &timeonday)
		}
	}
	// log.Info().Msgf("%v %v %v", timeonmonth, timeonweek, timeonday)
	availabilityinfo = collector.Availability{
		Day:   uint64(timeonday.Minutes()),
		Week:  uint64(timeonweek.Minutes()),
		Month: uint64(timeonmonth.Minutes()),
	}

	// SERVICES
	var servicesinfo collector.Services

	services_key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services`,
		registry.READ|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err == nil {
		defer services_key.Close()
		services, err := services_key.ReadSubKeyNames(-1)
		if err == nil {
			for _, service := range services {
				service_key, err := registry.OpenKey(services_key, service,
					registry.READ|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
				if err == nil {
					defer service_key.Close()
					displayname, _, _ := service_key.GetStringValue("DisplayName")
					description, _, _ := service_key.GetStringValue("Description")
					objectname, _, _ := service_key.GetStringValue("ObjectName")
					objectnamesid, _ := winio.LookupSidByName(objectname)
					imagepath, _, _ := service_key.GetStringValue("ImagePath")

					// Grab ImagePath key security
					_, registrydacl, _ := windowssecurity.GetOwnerAndDACL(`MACHINE\SYSTEM\CurrentControlSet\Services\`+service+``, windows.SE_REGISTRY_KEY)

					// let's see if we can grab a DACL
					var imagepathowner string
					var imageexecutable string
					var imagepathdacl []byte
					if imagepath != "" {
						// Windows service executable names is a hot effin mess
						if strings.HasPrefix(strings.ToLower(imagepath), `system32\`) {
							imagepath = `%SystemRoot%\` + imagepath
						} else if strings.HasPrefix(imagepath, `\SystemRoot\`) {
							imagepath = `%SystemRoot%\` + imagepath[12:]
						}

						// find the executable name ... windows .... arrrgh
						var executable string
						if imagepath[0] == '"' {
							// Quoted
							nextquote := strings.Index(imagepath[1:], `"`)
							if nextquote != -1 {
								executable = imagepath[1 : nextquote+1]
							}
						} else {
							// Unquoted
							trypath := imagepath
							for {
								statpath, _ := registry.ExpandString(trypath)
								if _, err := os.Stat(statpath); err == nil {
									executable = trypath
									break
								}
								lastspace := strings.LastIndex(trypath, " ")
								if lastspace == -1 {
									break // give up
								}
								trypath = imagepath[:lastspace]
								if !strings.HasSuffix(strings.ToLower(trypath), ".exe") {
									trypath += ".exe"
								}
							}
						}
						executable, _ = registry.ExpandString(executable)
						imageexecutable = executable
						if executable != "" {
							ownersid, dacl, err := windowssecurity.GetOwnerAndDACL(executable, windows.SE_FILE_OBJECT)
							if err == nil {
								imagepathowner = ownersid.String()
							}
							imagepathdacl = dacl
						}
					}

					start, _, _ := service_key.GetIntegerValue("Start")
					stype, _, _ := service_key.GetIntegerValue("Type")
					if stype >= 16 {
						servicesinfo = append(servicesinfo, collector.Service{
							RegistryDACL:         registrydacl,
							Name:                 service,
							DisplayName:          displayname,
							Description:          description,
							ImagePath:            imagepath,
							ImageExecutable:      imageexecutable,
							ImageExecutableOwner: imagepathowner,
							ImageExecutableDACL:  imagepathdacl,
							Start:                int(start),
							Type:                 int(stype),
							Account:              objectname,
							AccountSID:           objectnamesid,
						})
					}
				}
			}
		}
	}

	// LOCAL USERS AND GROUPS
	var usersinfo collector.Users
	users, _ := winapi.ListLocalUsers()
	for _, user := range users {
		usersinfo = append(usersinfo, collector.User{
			Name:                 user.Username,
			SID:                  user.SID,
			FullName:             user.FullName,
			IsEnabled:            user.IsEnabled,
			IsLocked:             user.IsLocked,
			IsAdmin:              user.IsAdmin,
			PasswordNeverExpires: user.PasswordNeverExpires,
			NoChangePassword:     user.NoChangePassword,
			PasswordLastSet:      user.PasswordAge.Time,
			LastLogon:            user.LastLogon.Time,
			LastLogoff:           user.LastLogoff.Time,
			BadPasswordCount:     int(user.BadPasswordCount),
			NumberOfLogins:       int(user.NumberOfLogons),
		})
	}

	// GROUPS
	var groupsinfo collector.Groups
	groups, _ := winapi.ListLocalGroups()
	for _, group := range groups {
		groupsid, _ := winio.LookupSidByName(group.Name)
		grp := collector.Group{
			Name: group.Name,
			SID:  groupsid,
		}
		members, _ := winapi.LocalGroupGetMembers(group.Name)
		for _, member := range members {
			membersid, _ := winio.LookupSidByName(member.DomainAndName)
			grp.Members = append(grp.Members, collector.Member{
				Name: member.DomainAndName,
				SID:  membersid,
			})
		}
		groupsinfo = append(groupsinfo, grp)
	}

	softwareinfo, _ := winapi.InstalledSoftwareList()

	hwinfo, osinfo, meminfo, _, _, _ := winapi.GetSystemProfile()

	info := collector.Info{
		Collected: time.Now(),
		BuildDate: builddate,
		Commit:    commit,

		Machine:         machineinfo,
		Hardware:        hwinfo,
		OperatingSystem: osinfo,
		Memory:          meminfo,

		Availability:    availabilityinfo,
		LoginPopularity: logininfo,

		Users:    usersinfo,
		Groups:   groupsinfo,
		Shares:   sharesinfo,
		Services: servicesinfo,
		Software: softwareinfo,
	}

	outputpath := flag.String("outputpath", "", "Dump output JSON file in this folder")

	flag.Parse()

	if *outputpath == "" {
		*outputpath = "."
	}

	targetname := info.Machine.Name + ".json"
	if info.Machine.IsDomainJoined {
		targetname = info.Machine.Name + "$" + info.Machine.Domain + ".json"
	}
	output, _ := json.MarshalIndent(info, "", "  ")
	outputfile := filepath.Join(*outputpath, targetname)
	err = ioutil.WriteFile(outputfile, output, 0600)
	if err != nil {
		log.Error().Msgf("Problem writing to file %v: %v", outputfile, err)
		os.Exit(1)
	}
	log.Info().Msgf("Information collected to file %v", outputfile)
}
