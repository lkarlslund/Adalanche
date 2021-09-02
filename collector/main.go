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
	winapi "github.com/lkarlslund/go-win64api"
	"github.com/lkarlslund/go-win64api/shared"
	"golang.org/x/sys/windows/registry"
)

type Info struct {
	Collected       time.Time
	Machine         Machine `json:",omitempty"`
	Hardware        shared.Hardware
	OperatingSystem shared.OperatingSystem
	Memory          shared.Memory
	LoginPopularity LoginPopularity
	Users           Users    `json:",omitempty"`
	Groups          Groups   `json:",omitempty"`
	Shares          Shares   `json:",omitempty"`
	Services        Services `json:",omitempty"`
}

type Machine struct {
	Name           string `json:",omitempty"`
	Domain         string `json:",omitempty"`
	IsDomainJoined bool   `json:",omitempty"`

	Architecture       string `json:",omitempty"`
	NumberOfProcessors int    `json:",omitempty"`

	ProductName        string `json:",omitempty"`
	EditionID          string `json:",omitempty"`
	ReleaseID          string `json:",omitempty"`
	BuildBranch        string `json:",omitempty"`
	MajorVersionNumber uint64 `json:",omitempty"`
	Version            string `json:",omitempty"`
	BuildNumber        string `json:",omitempty"`

	DefaultUsername    string `json:",omitempty"`
	DefaultDomain      string `json:",omitempty"`
	AltDefaultUsername string `json:",omitempty"`
	AltDefaultDomain   string `json:",omitempty"`

	UACConsentPromptBehaviorAdmin    uint64 `json:",omitempty"`
	UACEnableLUA                     uint64 `json:",omitempty"`
	UACLocalAccountTokenFilterPolicy uint64 `json:",omitempty"`
	UACFilterAdministratorToken      uint64 `json:",omitempty"`
}

type LoginPopularity struct {
	Day   []LoginCount
	Week  []LoginCount
	Month []LoginCount
}

type LoginCount struct {
	Name  string
	SID   string
	Count uint64
}

type Shares []Share
type Share struct {
	Name        string `json:",omitempty"`
	Path        string `json:",omitempty"`
	Remark      string `json:",omitempty"`
	Permissions int    `json:",omitempty"`
	Type        int    `json:",omitempty"`
	DACL        []byte `json:",omitempty"`
}

type Services []Service
type Service struct {
	Name        string
	DisplayName string
	Description string

	ImagePath string

	Start int
	Type  int

	Account    string
	AccountSID string
}

type Users []User
type User struct {
	Name                 string
	SID                  string
	FullName             string
	IsEnabled            bool
	IsLocked             bool
	IsAdmin              bool
	PasswordNeverExpires bool
	NoChangePassword     bool
	PasswordLastSet      time.Time
	LastLogon            time.Time
	BadPasswordCount     int
	NumberOfLogins       int
}

type Groups []Group
type Group struct {
	Name    string
	SID     string
	Comment string
	Members []Member
}
type Member struct {
	Name string
	SID  string
}

func main() {
	// MACHINE
	hostname, _ := os.Hostname()

	var domain *uint16
	var status uint32
	syscall.NetGetJoinInformation(nil, &domain, &status)
	defer syscall.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))

	numcpus, _ := strconv.Atoi(os.Getenv(`NUMBER_OF_PROCESSORS`))
	machineinfo := Machine{
		Name:               hostname,
		Domain:             winapi.UTF16toString(domain),
		IsDomainJoined:     status == syscall.NetSetupDomainName,
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
	var sharesinfo Shares

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
					shareinfo := Share{
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
	amonthago := time.Now().Add(-30 * 24 * time.Hour)
	aweekago := time.Now().Add(-7 * 24 * time.Hour)
	adayago := time.Now().Add(-1 * 24 * time.Hour)
	monthmap := make(map[string]uint64)
	weekmap := make(map[string]uint64)
	daymap := make(map[string]uint64)

	log, err := winevent.NewStream(winevent.EventStreamParams{
		Channel:  "Microsoft-Windows-Winlogon/Operational",
		EventIDs: "811,812",
		BuffSize: 2048000,
	}, 0)

	if err == nil {
		for {
			events, _, _, err := log.Read()
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
	var logininfo LoginPopularity
	for usersid, count := range monthmap {
		var name, domain string
		sid, err := syscall.StringToSid(usersid)
		if err == nil {
			name, domain, _, err = sid.LookupAccount("")
		}
		logininfo.Month = append(logininfo.Month, LoginCount{
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
		logininfo.Week = append(logininfo.Week, LoginCount{
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
		logininfo.Day = append(logininfo.Day, LoginCount{
			Name:  domain + "\\" + name,
			SID:   usersid,
			Count: count,
		})
	}

	// SERVICES
	var servicesinfo Services

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
					start, _, _ := service_key.GetIntegerValue("Start")
					stype, _, _ := service_key.GetIntegerValue("Type")
					if stype >= 16 {
						servicesinfo = append(servicesinfo, Service{
							Name:        service,
							DisplayName: displayname,
							Description: description,
							ImagePath:   imagepath,
							Start:       int(start),
							Type:        int(stype),
							Account:     objectname,
							AccountSID:  objectnamesid,
						})
					}
				}
			}
		}
	}

	// LOCAL USERS AND GROUPS
	var usersinfo Users
	users, _ := winapi.ListLocalUsers()
	for _, user := range users {
		usersid, _ := winio.LookupSidByName(user.Username)
		usersinfo = append(usersinfo, User{
			Name:                 user.Username,
			SID:                  usersid,
			FullName:             user.FullName,
			IsEnabled:            user.IsEnabled,
			IsLocked:             user.IsLocked,
			IsAdmin:              user.IsAdmin,
			PasswordNeverExpires: user.PasswordNeverExpires,
			NoChangePassword:     user.NoChangePassword,
			PasswordLastSet:      user.PasswordAge.Time,
			LastLogon:            user.LastLogon.Time,
			BadPasswordCount:     int(user.BadPasswordCount),
			NumberOfLogins:       int(user.NumberOfLogons),
		})
	}

	// GROUPS
	var groupsinfo Groups
	groups, _ := winapi.ListLocalGroups()
	for _, group := range groups {
		groupsid, _ := winio.LookupSidByName(group.Name)
		grp := Group{
			Name: group.Name,
			SID:  groupsid,
		}
		members, _ := winapi.LocalGroupGetMembers(group.Name)
		for _, member := range members {
			membersid, _ := winio.LookupSidByName(member.DomainAndName)
			grp.Members = append(grp.Members, Member{
				Name: member.DomainAndName,
				SID:  membersid,
			})
		}
		groupsinfo = append(groupsinfo, grp)
	}
	hwinfo, osinfo, meminfo, _, _, _ := winapi.GetSystemProfile()

	info := Info{
		Collected:       time.Now(),
		Machine:         machineinfo,
		Hardware:        hwinfo,
		OperatingSystem: osinfo,
		Memory:          meminfo,
		LoginPopularity: logininfo,
		Users:           usersinfo,
		Groups:          groupsinfo,
		Shares:          sharesinfo,
		Services:        servicesinfo,
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

	ioutil.WriteFile(filepath.Join(*outputpath, targetname), output, 0600)
	// fmt.Print(string(output))
}
