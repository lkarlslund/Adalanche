package collect

import (
	"bytes"
	"maps"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	winio "github.com/Microsoft/go-winio"
	"github.com/amidaware/taskmaster"
	"github.com/antchfx/xmlquery"
	ewin "github.com/elastic/go-windows"
	"github.com/gravwell/gravwell/v3/winevent"
	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/version"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	winapi "github.com/lkarlslund/go-win64api"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func Collect() (localmachine.Info, error) {
	if !is64Bit && os64Bit {
		ui.Debug().Msgf("Running as 32-bit on 64-bit system")
	}

	isUnprivileged := !windows.GetCurrentProcessToken().IsElevated()

	if isUnprivileged {
		ui.Warn().Msg("Collection is being run as an unelevated process. This will limit collected data and affect analysis results. ")
	}

	// MACHINE
	hostname, _ := os.Hostname()
	hostsid, _ := winio.LookupSidByName(hostname)

	var domain *uint16
	var status uint32
	syscall.NetGetJoinInformation(nil, &domain, &status)
	defer syscall.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))

	sysinfo, err := ewin.GetNativeSystemInfo()
	if err != nil {
		ui.Warn().Msgf("Problem getting system information: %v", err)
	}

	isdomainjoined := status == syscall.NetSetupDomainName
	var hostdomainsid string
	if isdomainjoined {
		hostdomainsid, _ = winio.LookupSidByName(hostname + "$")
	}

	machineinfo := localmachine.Machine{
		Name:               hostname,
		LocalSID:           hostsid,
		Domain:             winapi.UTF16toString(domain),
		IsDomainJoined:     isdomainjoined,
		ComputerDomainSID:  hostdomainsid,
		Architecture:       sysinfo.ProcessorArchitecture.String(),
		NumberOfProcessors: int(sysinfo.NumberOfProcessors),
	}

	var interfaceinfo []localmachine.NetworkInterfaceInfo

	interfaces, err := net.Interfaces()
	if err != nil {
		ui.Warn().Msgf("Problem getting network adapter information: %v", err)
	} else {
		for _, iface := range interfaces {
			addrs, _ := iface.Addrs()
			var addrstrings []string
			for _, addr := range addrs {
				addrstrings = append(addrstrings, addr.String())
			}
			interfaceinfo = append(interfaceinfo, localmachine.NetworkInterfaceInfo{
				Name:       iface.Name,
				MACAddress: iface.HardwareAddr.String(),
				Flags:      uint(iface.Flags),
				Addresses:  addrstrings,
			})
		}
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
		machineinfo.DisplayVersion, _, _ = currentversion_key.GetStringValue("DisplayVersion")
		machineinfo.BuildLab, _, _ = currentversion_key.GetStringValue("BuildLab")
		machineinfo.LCUVer, _, _ = currentversion_key.GetStringValue("LCUVer")
		UBR, _, _ := currentversion_key.GetStringValue("UBR")
		if UBR != "" {
			machineinfo.BuildNumber += "." + UBR
		}
	}

	productoptions_key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\ProductOptions`,
		registry.READ|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err == nil {
		defer productoptions_key.Close()
		machineinfo.ProductType, _, _ = productoptions_key.GetStringValue("ProductType")
		ptypes, _, err := productoptions_key.GetStringsValue("ProductSuite")
		if err == nil {
			machineinfo.ProductSuite = strings.Join(ptypes, ", ")
		}
	}

	// We use this in order to not collect 4612 events from DCs
	// isdomaincontroller := strings.EqualFold(cinfo.Machine.ProductType, "LANMANNT")

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
					var skipit bool
					for _, existingcache := range machineinfo.AppCache {
						if bytes.Equal(existingcache, cache) {
							skipit = true
							break
						}
					}
					if !skipit {
						machineinfo.AppCache = append(machineinfo.AppCache, cache)
					}
				}
			}
		}
	}

	// SCCM SETTINGS
	ccmsetup_key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\CCMSetup`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == nil {
		defer ccmsetup_key.Close()
		machineinfo.SCCMLastValidMP, _, _ = ccmsetup_key.GetStringValue(`LastValidMP`)
	}

	// WSUS SETTINGS
	wu_key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == nil {
		defer wu_key.Close()
		machineinfo.WUServer, _, _ = wu_key.GetStringValue(`WUServer`)
		machineinfo.WUStatusServer, _, _ = wu_key.GetStringValue(`WUStatusServer`)
	}

	// SHARES
	var sharesinfo localmachine.Shares

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
					shareinfo := localmachine.Share{
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

					if shareinfo.Path != "" {
						ownersid, dacl, err := windowssecurity.GetOwnerAndDACL(shareinfo.Path, windows.SE_FILE_OBJECT)
						if err == nil {
							shareinfo.PathOwner = ownersid.String()
							shareinfo.PathDACL = dacl
						}
					}

					// if stype >= 16 {
					sharesinfo = append(sharesinfo, shareinfo)
					// }
				}
			}
		}
	}

	// SCHEDULED TASKS
	var scheduledtasksinfo taskmaster.RegisteredTaskCollection
	ts, err := taskmaster.Connect()
	if err == nil {
		scheduledtasksinfo, err = ts.GetRegisteredTasks()
		if err == nil {
			scheduledtasksinfo.Release()
		}
		ts.Disconnect()
	}

	// GATHER INTERESTING STUFF FROM EVENT ui

	// chn, _ := wineventlog.Channels()
	// for _, channel := range chn {
	// 	fmt.Println(channel)
	// }

	// Who has logged on and when https://nasbench.medium.com/finding-forensic-goodness-in-obscure-windows-event-logs-60e978ea45a3
	// Event 811 and 812 :-)
	type LogonTypeUser struct {
		User                      string
		LogonType                 uint32
		AuthenticationPackageName string
	}

	loginmap := make(map[LogonTypeUser]localmachine.LogonInfo)

	/*
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
							// LoginType

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
	*/

	// // Security Logs
	slog, err := winevent.NewStream(winevent.EventStreamParams{
		Channel:  "Security",
		EventIDs: "4624",
		BuffSize: 2048000,
	}, 0)

	if err != nil {
		ui.Error().Msgf("Problem opening security event log: %v", err)
	} else {
		for {
			events, _, _, err := slog.Read()
			if err != nil {
				ui.Error().Msgf("Problem getting more events: %v", err)
				break
			}

			for _, event := range events {
				// fmt.Println(string(event.Buff))

				doc, err := xmlquery.Parse(bytes.NewReader(bytes.Trim(event.Buff, "\x00")))
				if err != nil {
					ui.Error().Msgf("Problem parsing XML of %v: %v", string(event.Buff), err)
				} else {
					i := xmlquery.FindOne(doc, "/Event/System/EventID")
					if i.InnerText() == "4624" {
						timestamp := xmlquery.FindOne(doc, "/Event/System/TimeCreated/@SystemTime")
						t, _ := time.Parse(time.RFC3339Nano, timestamp.InnerText())

						logontype := xmlquery.FindOne(doc, `/Event/EventData/Data[@Name='LogonType']`).InnerText()
						targetusersid := xmlquery.FindOne(doc, `/Event/EventData/Data[@Name='TargetUserSid']`).InnerText()
						targetusername := xmlquery.FindOne(doc, `/Event/EventData/Data[@Name='TargetUserName']`).InnerText()
						targetdomainname := xmlquery.FindOne(doc, `/Event/EventData/Data[@Name='TargetDomainName']`).InnerText()
						authenticationpackagename := xmlquery.FindOne(doc, `/Event/EventData/Data[@Name='AuthenticationPackageName']`).InnerText()
						lmpackagename := xmlquery.FindOne(doc, `/Event/EventData/Data[@Name='LmPackageName']`).InnerText()
						logontypeint, _ := strconv.ParseInt(logontype, 10, 32)
						ipaddress := xmlquery.FindOne(doc, `/Event/EventData/Data[@Name='IpAddress']`).InnerText()
						if ipaddress == "244.230.0.0" { // Avoid Windows 7 RDP 8.0 bug - https://learn.microsoft.com/en-us/troubleshoot/windows-client/remote/invalid-client-ip-address-port-number-event-4624
							ipaddress = ""
						}

						if len(lmpackagename) > 1 {
							authenticationpackagename = lmpackagename
						}

						lookup := LogonTypeUser{
							LogonType:                 uint32(logontypeint),
							User:                      targetdomainname + "/" + targetusername,
							AuthenticationPackageName: authenticationpackagename,
						}
						entry, found := loginmap[lookup]
						if !found {
							entry = localmachine.LogonInfo{
								User:                      targetusername,
								Domain:                    targetdomainname,
								SID:                       targetusersid,
								LogonType:                 uint32(logontypeint),
								AuthenticationPackageName: authenticationpackagename,
								FirstSeen:                 t,
								LastSeen:                  t,
								Count:                     1,
							}
							if len(ipaddress) > 1 {
								entry.IpAddress = []string{ipaddress}
							}
						} else {
							if entry.SID == "" {
								entry.SID = targetusersid
							}
							if t.Before(entry.FirstSeen) {
								entry.FirstSeen = t
							}
							if t.After(entry.LastSeen) {
								entry.LastSeen = t
							}
							if len(ipaddress) > 1 && !slices.Contains(entry.IpAddress, ipaddress) {
								entry.IpAddress = append(entry.IpAddress, ipaddress)
							}
							entry.Count++
						}
						ui.Debug().Msgf("Updating login map %v to %v", lookup, entry)
						loginmap[lookup] = entry
					} else {
						ui.Info().Msgf("Skipping event %v", string(event.Buff))
					}
				}
			}
		}
	}

	// MACHINE AVAILABILITY
	var timeonmonth, timeonweek, timeonday time.Duration
	elog, err := winevent.NewStream(winevent.EventStreamParams{
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

	var availabilityinfo localmachine.Availability
	var laststart, laststop time.Time
	laststart = laststart.Add(time.Minute) // First hit in event ui might be a shutdown event, so we just assume it was powered on ages ago
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
												// ui.Info().Msgf("%v -> %v", laststart, laststop)
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
								// ui.Info().Msgf("%v %v %v %v", t, providername, eventid, string(event.Buff))
								// ui.Info().Msgf("%v %v %v", t, providername, eventid)
							}
						case "12": // Startup
							if providername == "Microsoft-Windows-Kernel-General" {
								laststart = t
								// ui.Info().Msgf("%v %v %v", t, providername, eventid)
							}
						case "13": // Shutdown
							if providername == "Microsoft-Windows-Kernel-General" {
								laststop = t
								// ui.Info().Msgf("%v %v %v", t, providername, eventid)
							}
						case "42": // Sleep
							if providername == "Microsoft-Windows-Kernel-Power" {
								laststop = t
								// ui.Info().Msgf("%v %v %v %v", t, providername, eventid, string(event.Buff))
								// ui.Info().Msgf("%v %v %v", t, providername, eventid)
							}
						case "6008": // Unexpected shutdown
							if providername == "Eventlog" {
								laststop = t
								// ui.Info().Msgf("%v %v %v", t, providername, eventid)
							}
						}
					}

					if !laststart.IsZero() && !laststop.IsZero() && laststart.Before(laststop) {
						// ui.Info().Msgf("%v -> %v", laststart, laststop)
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
	// ui.Info().Msgf("%v %v %v", timeonmonth, timeonweek, timeonday)
	availabilityinfo = localmachine.Availability{
		Day:   uint64(timeonday.Minutes()),
		Week:  uint64(timeonweek.Minutes()),
		Month: uint64(timeonmonth.Minutes()),
	}

	// SERVICE CONTROL MANAGER SECURITY DESCRIPTOR FROM REGISTRY
	var scmsd []byte
	securitykey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\Security`, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		ui.Warn().Msgf("Problem opening service security key for service control manager: %v, skipping\n", err)
	} else {
		defer securitykey.Close()
		// Read the security descriptor
		scmsd, _, err = securitykey.GetBinaryValue("Security")
		if err != nil {
			ui.Error().Msgf("Problem reading security descriptor for service control manager: %v, skipping\n", err)
		}
	}

	// SERVICES
	var servicesinfo localmachine.Services
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
					stype, _, _ := service_key.GetIntegerValue("Type")
					if stype >= 16 {
						// get service details
						displayname, _, _ := service_key.GetStringValue("DisplayName")
						description, _, _ := service_key.GetStringValue("Description")
						objectname, _, _ := service_key.GetStringValue("ObjectName")
						objectnamesid, _ := winio.LookupSidByName(objectname)
						imagepath, _, _ := service_key.GetStringValue("ImagePath")
						requiredPrivileges, _, _ := service_key.GetStringsValue("RequiredPrivileges")
						start, _, _ := service_key.GetIntegerValue("Start")

						// Grab service key security
						registryowner, registrydacl, _ := windowssecurity.GetOwnerAndDACL(`MACHINE\SYSTEM\CurrentControlSet\Services\`+service+``, windows.SE_REGISTRY_KEY)

						// get security descriptor under Security/Security
						var sd []byte
						service_key_security, err := registry.OpenKey(service_key, `Security`,
							registry.READ|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
						if err == nil {
							sd, _, _ = service_key_security.GetBinaryValue("Security")
						}

						// let's see if we can grab a DACL
						var imagepathowner string
						var imageexecutable string
						var imagepathdacl []byte

						if imagepath != "" {
							// Windows service executable names is a hot effin mess
							if strings.HasPrefix(strings.ToLower(imagepath), `system32\`) {
								// Avoid mapping on 32-bit on 64-bit SYSWOW
								imagepath = `%SystemRoot%\` + imagepath
							} else if strings.HasPrefix(imagepath, `\SystemRoot\`) {
								imagepath = `%SystemRoot%\` + imagepath[12:]
							} else if strings.HasPrefix(imagepath, `\??\`) {
								imagepath = imagepath[4:]
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
									statpath := resolvepath(trypath)
									ui.Debug().Msgf("Trying %v -> %v", trypath, statpath)
									if _, err = os.Stat(statpath); err == nil {
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
							ui.Debug().Msgf("Imagepath %v is mapped to executable %v", imagepath, executable)
							executable = resolvepath(executable)
							imageexecutable = executable
							if executable != "" {
								ownersid, dacl, err := windowssecurity.GetOwnerAndDACL(executable, windows.SE_FILE_OBJECT)
								if err == nil {
									imagepathowner = ownersid.String()
									imagepathdacl = dacl
								} else {
									ui.Warn().Msgf("Problem getting security info for %v: %v", executable, err)
								}
							} else {
								ui.Warn().Msgf("Could not resolve executable %v", imagepath)
							}
						}

						servicesinfo = append(servicesinfo, localmachine.Service{
							RegistryOwner:        registryowner.String(),
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
							RequiredPrivileges:   requiredPrivileges,
							SecurityDescriptor:   sd,
						})
					}
					service_key.Close()
				}
			}
		}
	}

	// LOCAL USERS AND GROUPS
	domainsid, _ := windowssecurity.ParseStringSID(machineinfo.ComputerDomainSID)

	var usersinfo localmachine.Users
	users, _ := winapi.ListLocalUsers()
	for _, user := range users {
		usersid, _ := windowssecurity.ParseStringSID(user.SID)
		if machineinfo.IsDomainJoined && usersid.StripRID() == domainsid.StripRID() {
			// This is a domain account, so we're running on a DC? skip it
			continue
		}

		usersinfo = append(usersinfo, localmachine.User{
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
	var groupsinfo localmachine.Groups
	groups, _ := winapi.ListLocalGroups()
	for _, group := range groups {
		groupsid, _ := winio.LookupSidByName(group.Name)
		grp := localmachine.Group{
			Name: group.Name,
			SID:  groupsid,
		}
		members, _ := winapi.LocalGroupGetMembers(group.Name)
		for _, member := range members {
			grp.Members = append(grp.Members, localmachine.Member{
				Name: member.DomainAndName,
				SID:  member.SID,
			})
		}
		groupsinfo = append(groupsinfo, grp)
	}

	registrydata := CollectRegistryItems()

	dumpedsoftwareinfo, _ := winapi.InstalledSoftwareList()
	var softwareinfo []localmachine.Software
	if len(dumpedsoftwareinfo) > 0 {
		softwareinfo = make([]localmachine.Software, len(dumpedsoftwareinfo))
		for i, sw := range dumpedsoftwareinfo {
			softwareinfo[i] = localmachine.Software{
				DisplayName:     sw.DisplayName,
				DisplayVersion:  sw.DisplayVersion,
				Arch:            sw.Arch,
				Publisher:       sw.Publisher,
				InstallDate:     sw.InstallDate,
				EstimatedSize:   sw.EstimatedSize,
				Contact:         sw.Contact,
				HelpLink:        sw.HelpLink,
				InstallSource:   sw.InstallSource,
				InstallLocation: sw.InstallLocation,
				UninstallString: sw.UninstallString,
				VersionMajor:    sw.VersionMajor,
				VersionMinor:    sw.VersionMinor,
			}
		}
	}

	// Fix this if we need the data later on
	// hwinfo, osinfo, meminfo, _, _, _ := winapi.GetSystemProfile()

	var privilegesinfo localmachine.Privileges
	pol, err := LsaOpenPolicy("", _POLICY_LOOKUP_NAMES|_POLICY_VIEW_LOCAL_INFORMATION)
	if err == nil {
		for _, privilege := range PRIVILEGE_NAMES {
			sids, err := LsaEnumerateAccountsWithUserRight(*pol, string(privilege))
			if err == nil {
				sidstrings := make([]string, len(sids))
				for i, sid := range sids {
					sidstrings[i] = sid.String()
				}
				privilegesinfo = append(privilegesinfo, localmachine.Privilege{
					Name:         string(privilege),
					AssignedSIDs: sidstrings,
				})
			} else if err != STATUS_NO_MORE_ENTRIES && err != NO_MORE_DATA_IS_AVAILABLE {
				ui.Warn().Msgf("Problem enumerating %v: %v", privilege, err)
			}
		}
		LsaClose(*pol)
	} else {
		ui.Warn().Msgf("Could not open LSA policy: %v", err)
	}

	info := localmachine.Info{
		Common: basedata.Common{
			Collector: "collector",
			Commit:    version.Commit,
			Collected: time.Now(),
		},
		UnprivilegedCollection: isUnprivileged, // Indicate if the collection was running with low privs, so we can issue annoying warnings when loading them
		Machine:                machineinfo,
		// Hardware: hwinfo,
		Network: localmachine.NetworkInformation{
			InternetConnectivity: TestInternet(),
			NetworkInterfaces:    interfaceinfo,
		},
		// OperatingSystem: osinfo,
		// Memory:          meminfo,
		Availability:                            availabilityinfo,
		LoginInfos:                              slices.Collect(maps.Values(loginmap)),
		Users:                                   usersinfo,
		Groups:                                  groupsinfo,
		RegistryData:                            registrydata,
		Shares:                                  sharesinfo,
		Services:                                servicesinfo,
		ServiceControlManagerSecurityDescriptor: scmsd,
		Software:                                softwareinfo,
		Tasks: func() []localmachine.RegisteredTask {
			tasks := make([]localmachine.RegisteredTask, len(scheduledtasksinfo))
			for i, task := range scheduledtasksinfo {
				tasks[i] = ConvertRegisteredTask(task)
			}
			return tasks
		}(),
		Privileges: privilegesinfo,
	}

	return info, nil
}
