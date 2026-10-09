package collect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	winio "github.com/Microsoft/go-winio"
	"github.com/amidaware/taskmaster"
	ewin "github.com/elastic/go-windows"
	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	winapi "github.com/lkarlslund/go-win64api"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Logon history is read newest first within this window, up to this many
// events. Busy servers and domain controllers can hold millions of logons.
const (
	logonEventWindow = 90 * 24 * time.Hour
	logonEventLimit  = 250000
	// Availability only reports the last month, day and week.
	availabilityEventWindow = 31 * 24 * time.Hour
	availabilityEventLimit  = 50000
)

// Each inventory section is an independent collector. Sections run in
// parallel after the machine identity is known; see RegisterCollector.
func init() {
	RegisterCollector(Collector{Name: "machine", Stage: StageIdentity, Collect: collectMachine})
	for _, c := range []Collector{
		{Name: "network", Collect: collectNetwork},
		{Name: "autologon", Collect: collectAutologon},
		{Name: "appcompat-cache", Collect: collectAppCompatCache},
		{Name: "management-agents", Collect: collectManagementAgents},
		{Name: "shares", Collect: collectShares},
		// The task scheduler library initializes its own single-threaded apartment.
		{Name: "tasks", Thread: ThreadLocked, Collect: collectTasks},
		{Name: "logons", Collect: collectLogons},
		{Name: "availability", Collect: collectAvailability},
		{Name: "services", Collect: collectServices},
		{Name: "users", Collect: collectUsers},
		{Name: "groups", Collect: collectGroups},
		{Name: "registry", Collect: collectRegistry},
		{Name: "software", Collect: collectSoftware},
		{Name: "privileges", Collect: collectPrivileges},
	} {
		c.Stage = StageInventory
		RegisterCollector(c)
	}
}

func openLocalMachineKey(path string, access uint32) (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, path, access|registry.WOW64_64KEY)
}

func collectMachine(env *Env) func(*Result) {
	outcomes := env.Outcomes
	if !is64Bit && os64Bit {
		ui.Debug().Msgf("Running as 32-bit on 64-bit system")
	}

	isUnprivileged := !windows.GetCurrentProcessToken().IsElevated()
	if isUnprivileged {
		ui.Warn().Msg("Collection is being run as an unelevated process. This will limit collected data and affect analysis results. ")
	}

	hostname, err := os.Hostname()
	outcomes["machine/hostname"] = basedata.CollectionResultFromError(err)
	hostsid, _ := winio.LookupSidByName(hostname)

	var domain *uint16
	var status uint32
	joinErr := syscall.NetGetJoinInformation(nil, &domain, &status)
	outcomes["machine/join-information"] = basedata.CollectionResultFromError(joinErr)
	if domain != nil {
		defer syscall.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))
	}

	sysinfo, err := ewin.GetNativeSystemInfo()
	outcomes["machine/system-information"] = basedata.CollectionResultFromError(err)
	if err != nil {
		ui.Warn().Msgf("Problem getting system information: %v", err)
	}

	isdomainjoined := joinErr == nil && status == syscall.NetSetupDomainName
	var hostdomainsid string
	if isdomainjoined {
		hostdomainsid, _ = winio.LookupSidByName(hostname + "$")
	}

	machineinfo := localmachine.Machine{
		Name:               hostname,
		LocalSID:           hostsid,
		IsDomainJoined:     isdomainjoined,
		ComputerDomainSID:  hostdomainsid,
		Architecture:       sysinfo.ProcessorArchitecture.String(),
		NumberOfProcessors: int(sysinfo.NumberOfProcessors),
	}
	if domain != nil {
		machineinfo.Domain = winapi.UTF16toString(domain)
	}
	smbiosuuid, err := collectSMBIOSUUID()
	outcomes["machine/smbios-uuid"] = basedata.CollectionResultFromError(err)
	machineinfo.SMBIOSUUID = smbiosuuid

	currentversion_key, err := openLocalMachineKey(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.READ)
	outcomes["machine/version"] = basedata.CollectionResultFromError(err)
	if err == nil {
		defer currentversion_key.Close()
		machineinfo.ProductName, _, _ = currentversion_key.GetStringValue("ProductName")
		machineinfo.EditionID, _, _ = currentversion_key.GetStringValue("EditionId")
		machineinfo.ReleaseID, _, _ = currentversion_key.GetStringValue("ReleaseId")
		machineinfo.BuildBranch, _, _ = currentversion_key.GetStringValue("BuildBranch")
		machineinfo.MajorVersionNumber, _, _ = currentversion_key.GetIntegerValue("CurrentVersionMajorNumber")
		machineinfo.Version, _, _ = currentversion_key.GetStringValue("CurrentVersion")
		machineinfo.DisplayVersion, _, _ = currentversion_key.GetStringValue("DisplayVersion")
		machineinfo.BuildLab, _, _ = currentversion_key.GetStringValue("BuildLab")
		machineinfo.LCUVer, _, _ = currentversion_key.GetStringValue("LCUVer")
	}
	machineinfo.BuildNumber = collectBuildNumber(windowssecurity.ReadRegistryKey, windowssecurity.ReadRegistryDWORD, outcomes)

	productoptions_key, err := openLocalMachineKey(`SYSTEM\CurrentControlSet\Control\ProductOptions`, registry.READ)
	outcomes["machine/product-options"] = basedata.CollectionResultFromError(err)
	if err == nil {
		defer productoptions_key.Close()
		machineinfo.ProductType, _, _ = productoptions_key.GetStringValue("ProductType")
		ptypes, _, err := productoptions_key.GetStringsValue("ProductSuite")
		if err == nil {
			machineinfo.ProductSuite = strings.Join(ptypes, ", ")
		}
	}

	return func(r *Result) {
		r.Info.Machine = machineinfo
		r.Info.UnprivilegedCollection = isUnprivileged // Indicate if the collection was running with low privs, so we can issue annoying warnings when loading them
	}
}

func collectNetwork(env *Env) func(*Result) {
	var interfaceinfo []localmachine.NetworkInterfaceInfo
	interfaces, err := net.Interfaces()
	env.Outcomes["network/interfaces"] = basedata.CollectionResultFromError(err)
	if err != nil {
		ui.Warn().Msgf("Problem getting network adapter information: %v", err)
	}
	for _, iface := range interfaces {
		addrs, addrErr := iface.Addrs()
		env.Outcomes["network/addresses/"+iface.Name] = basedata.CollectionResultFromError(addrErr)
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
	connectivity := TestInternet()
	return func(r *Result) {
		r.Info.Network = localmachine.NetworkInformation{
			InternetConnectivity: connectivity,
			NetworkInterfaces:    interfaceinfo,
		}
	}
}

// AUTOLOGON - FREE CREDENTIALS. Only the account is kept, never the password.
func collectAutologon(env *Env) func(*Result) {
	winlogon_key, err := openLocalMachineKey(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.QUERY_VALUE)
	env.Outcomes["autologon/open"] = basedata.CollectionResultFromError(err)
	if err != nil {
		return nil
	}
	defer winlogon_key.Close()
	var username, domain, altusername, altdomain string
	if pwd, _, _ := winlogon_key.GetStringValue(`DefaultPassword`); pwd != "" {
		username, _, _ = winlogon_key.GetStringValue(`DefaultUsername`)
		domain, _, _ = winlogon_key.GetStringValue(`DefaultDomain`)
	}
	if pwd, _, _ := winlogon_key.GetStringValue(`AltDefaultPassword`); pwd != "" {
		altusername, _, _ = winlogon_key.GetStringValue(`AltDefaultUsername`)
		altdomain, _, _ = winlogon_key.GetStringValue(`AltDefaultDomain`)
	}
	return func(r *Result) {
		r.Info.Machine.DefaultUsername, r.Info.Machine.DefaultDomain = username, domain
		r.Info.Machine.AltDefaultUsername, r.Info.Machine.AltDefaultDomain = altusername, altdomain
	}
}

// APP COMPAT CACHE - LAST 1024 PROGRAM EXECUTIONS
func collectAppCompatCache(env *Env) func(*Result) {
	system_key, err := openLocalMachineKey(`SYSTEM`, registry.ENUMERATE_SUB_KEYS)
	env.Outcomes["appcompat-cache/open"] = basedata.CollectionResultFromError(err)
	if err != nil {
		return nil
	}
	defer system_key.Close()
	subnames, err := system_key.ReadSubKeyNames(-1)
	env.Outcomes["appcompat-cache/enumerate"] = basedata.CollectionResultFromError(err)
	var caches [][]byte
	for _, subkey := range subnames {
		if !strings.HasPrefix(strings.ToLower(subkey), "controlset") {
			continue
		}
		appcache_key, err := registry.OpenKey(system_key, subkey+`\Control\Session Manager\AppCompatCache`, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		cache, _, err := appcache_key.GetBinaryValue(`AppCompatCache`)
		appcache_key.Close()
		env.Outcomes["appcompat-cache/value/"+subkey] = basedata.CollectionResultFromError(err)
		if err == nil && !containsBytes(caches, cache) {
			caches = append(caches, cache)
		}
	}
	return func(r *Result) { r.Info.Machine.AppCache = caches }
}

func containsBytes(list [][]byte, value []byte) bool {
	for _, existing := range list {
		if bytes.Equal(existing, value) {
			return true
		}
	}
	return false
}

func collectManagementAgents(env *Env) func(*Result) {
	var sccm, wuserver, wustatus string
	// SCCM SETTINGS
	ccmsetup_key, err := openLocalMachineKey(`SOFTWARE\Microsoft\CCMSetup`, registry.QUERY_VALUE)
	env.Outcomes["management/sccm"] = basedata.CollectionResultFromError(err)
	if err == nil {
		sccm, _, _ = ccmsetup_key.GetStringValue(`LastValidMP`)
		ccmsetup_key.Close()
	}
	// WSUS SETTINGS
	wu_key, err := openLocalMachineKey(`SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, registry.QUERY_VALUE)
	env.Outcomes["management/wsus"] = basedata.CollectionResultFromError(err)
	if err == nil {
		wuserver, _, _ = wu_key.GetStringValue(`WUServer`)
		wustatus, _, _ = wu_key.GetStringValue(`WUStatusServer`)
		wu_key.Close()
	}
	return func(r *Result) {
		r.Info.Machine.SCCMLastValidMP = sccm
		r.Info.Machine.WUServer, r.Info.Machine.WUStatusServer = wuserver, wustatus
	}
}

func collectShares(env *Env) func(*Result) {
	outcomes := env.Outcomes
	var sharesinfo localmachine.Shares

	shares_key, err := openLocalMachineKey(`SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`, registry.READ)
	outcomes["shares/open"] = basedata.CollectionResultFromError(err)
	if err != nil {
		return nil
	}
	defer shares_key.Close()
	permissions_key, err := registry.OpenKey(shares_key, `Security`, registry.READ|registry.WOW64_64KEY)
	outcomes["shares/security-open"] = basedata.CollectionResultFromError(err)
	if err != nil {
		return nil
	}
	defer permissions_key.Close()

	shares, err := shares_key.ReadValueNames(-1)
	outcomes["shares/enumerate"] = basedata.CollectionResultFromError(err)
	for _, share := range shares {
		permissions, _, permissionErr := permissions_key.GetBinaryValue(share)
		outcomes["shares/security/"+share] = basedata.CollectionResultFromError(permissionErr)
		shareinfo := localmachine.Share{
			Name: share,
			DACL: permissions,
		}

		share_settings, _, err := shares_key.GetStringsValue(share)
		outcomes["shares/settings/"+share] = basedata.CollectionResultFromError(err)
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

		if shareinfo.Path != "" {
			ownersid, dacl, err := windowssecurity.GetOwnerAndDACL(shareinfo.Path, windows.SE_FILE_OBJECT)
			outcomes["shares/path-security/"+share] = basedata.CollectionResultFromError(err)
			if err == nil {
				shareinfo.PathOwner = ownersid.String()
				shareinfo.PathDACL = dacl
			}
		}
		sharesinfo = append(sharesinfo, shareinfo)
	}
	return func(r *Result) { r.Info.Shares = sharesinfo }
}

func collectTasks(env *Env) func(*Result) {
	ts, err := taskmaster.Connect()
	env.Outcomes["tasks/connect"] = basedata.CollectionResultFromError(err)
	if err != nil {
		return nil
	}
	defer ts.Disconnect()
	scheduledtasksinfo, err := ts.GetRegisteredTasks()
	env.Outcomes["tasks/enumerate"] = basedata.CollectionResultFromError(err)
	if err != nil {
		return nil
	}
	defer scheduledtasksinfo.Release()
	tasks := make([]localmachine.RegisteredTask, len(scheduledtasksinfo))
	for i, task := range scheduledtasksinfo {
		tasks[i] = ConvertRegisteredTaskWithResults(task, env.Outcomes)
	}
	return func(r *Result) { r.Info.Tasks = tasks }
}

// eventLogResult records a bounded event-log read. Reaching the event limit is
// recorded as a collection limit, so an incomplete history is never mistaken
// for a complete one.
func eventLogResult(truncated bool, unparsed int, err error) basedata.CollectionResult {
	result := nativeCollectionResult(err)
	if result.Status == basedata.CollectionCollected {
		switch {
		case truncated:
			result.ErrorCode = "collection_limit"
		case unparsed > 0:
			result.ErrorCode = "unparsed_events"
		}
	}
	return result
}

// Who has logged on and when, newest first within the logon window.
func collectLogons(env *Env) func(*Result) {
	logons := newLogonAggregator()
	unparsed := 0
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	query := fmt.Sprintf("*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= %d]]]", logonEventWindow.Milliseconds())
	truncated, err := readNativeEvents(ctx, "Security", query, evtQueryReverseDirection, logonEventLimit, func(raw string) error {
		if logons.add([]byte(raw)) != nil {
			unparsed++ // Event text is not logged: it names users and addresses.
		}
		return nil
	})
	env.Outcomes["events/logons"] = eventLogResult(truncated, unparsed, err)
	if err != nil {
		ui.Warn().Msgf("Problem reading logon events: %v", err)
	}
	if unparsed > 0 {
		ui.Warn().Msgf("Skipped %v logon events that could not be interpreted", unparsed)
	}
	result := logons.logons()
	return func(r *Result) { r.Info.LoginInfos = result }
}

// MACHINE AVAILABILITY from power and boot events, oldest first.
func collectAvailability(env *Env) func(*Result) {
	tracker := newAvailabilityTracker(time.Now())
	unparsed := 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	query := fmt.Sprintf("*[System[Provider[@Name='Eventlog' or @Name='Microsoft-Windows-Kernel-General' or @Name='Microsoft-Windows-Kernel-Power' or @Name='Microsoft-Windows-Power-Troubleshooter'] and (EventID=1 or EventID=12 or EventID=13 or EventID=42 or EventID=6008) and TimeCreated[timediff(@SystemTime) <= %d]]]", availabilityEventWindow.Milliseconds())
	truncated, err := readNativeEvents(ctx, "System", query, evtQueryForwardDirection, availabilityEventLimit, func(raw string) error {
		if tracker.add([]byte(raw)) != nil {
			unparsed++
		}
		return nil
	})
	env.Outcomes["events/availability"] = eventLogResult(truncated, unparsed, err)
	if err != nil {
		return nil // Without events, uptime is unknown rather than zero.
	}
	availability := tracker.result()
	return func(r *Result) { r.Info.Availability = availability }
}

func collectServices(env *Env) func(*Result) {
	outcomes := env.Outcomes

	// SERVICE CONTROL MANAGER SECURITY DESCRIPTOR FROM REGISTRY
	var scmsd []byte
	securitykey, err := openLocalMachineKey(`SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\Security`, registry.QUERY_VALUE)
	if err != nil {
		ui.Warn().Msgf("Problem opening service security key for service control manager: %v, skipping\n", err)
	} else {
		scmsd, _, err = securitykey.GetBinaryValue("Security")
		securitykey.Close()
		if err != nil {
			ui.Error().Msgf("Problem reading security descriptor for service control manager: %v, skipping\n", err)
		}
	}
	outcomes["services/manager-security"] = basedata.CollectionResultFromError(err)

	var servicesinfo localmachine.Services
	services_key, err := openLocalMachineKey(`SYSTEM\CurrentControlSet\Services`, registry.READ)
	outcomes["services/open"] = basedata.CollectionResultFromError(err)
	if err == nil {
		defer services_key.Close()
		services, err := services_key.ReadSubKeyNames(-1)
		outcomes["services/enumerate"] = basedata.CollectionResultFromError(err)
		for _, service := range services {
			if s, ok := collectService(services_key, service, outcomes); ok {
				servicesinfo = append(servicesinfo, s)
			}
		}
	}
	return func(r *Result) {
		r.Info.ServiceControlManagerSecurityDescriptor = scmsd
		r.Info.Services = servicesinfo
	}
}

func collectService(services_key registry.Key, service string, outcomes basedata.CollectionResults) (localmachine.Service, bool) {
	service_key, err := registry.OpenKey(services_key, service, registry.READ|registry.WOW64_64KEY)
	outcomes["services/open/"+service] = basedata.CollectionResultFromError(err)
	if err != nil {
		return localmachine.Service{}, false
	}
	defer service_key.Close()
	stype, _, typeErr := service_key.GetIntegerValue("Type")
	outcomes["services/type/"+service] = basedata.CollectionResultFromError(typeErr)
	if stype < 16 {
		return localmachine.Service{}, false
	}
	// get service details
	displayname, _, _ := service_key.GetStringValue("DisplayName")
	description, _, _ := service_key.GetStringValue("Description")
	objectname, _, _ := service_key.GetStringValue("ObjectName")
	objectnamesid, _ := winio.LookupSidByName(objectname)
	imagepath, _, _ := service_key.GetStringValue("ImagePath")
	requiredPrivileges, _, _ := service_key.GetStringsValue("RequiredPrivileges")
	start, _, _ := service_key.GetIntegerValue("Start")

	// Grab service key security
	registryowner, registrydacl, aclErr := windowssecurity.GetOwnerAndDACL(`MACHINE\SYSTEM\CurrentControlSet\Services\`+service, windows.SE_REGISTRY_KEY)
	outcomes["services/registry-security/"+service] = basedata.CollectionResultFromError(aclErr)

	// get security descriptor under Security/Security
	var sd []byte
	service_key_security, err := registry.OpenKey(service_key, `Security`, registry.READ|registry.WOW64_64KEY)
	if err == nil {
		sd, _, err = service_key_security.GetBinaryValue("Security")
		service_key_security.Close()
	}
	outcomes["services/security/"+service] = basedata.CollectionResultFromError(err)

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
		if strings.HasPrefix(imagepath, `"`) {
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
			outcomes["services/executable-security/"+service] = basedata.CollectionResultFromError(err)
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

	return localmachine.Service{
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
	}, true
}

// LOCAL USERS
func collectUsers(env *Env) func(*Result) {
	machine := env.Info.Machine
	domainsid, _ := windowssecurity.ParseStringSID(machine.ComputerDomainSID)

	var usersinfo localmachine.Users
	users, usersErr := winapi.ListLocalUsers()
	env.Outcomes["users/enumerate"] = basedata.CollectionResultFromError(usersErr)
	for _, user := range users {
		usersid, _ := windowssecurity.ParseStringSID(user.SID)
		if machine.IsDomainJoined && usersid.StripRID() == domainsid.StripRID() {
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
	return func(r *Result) { r.Info.Users = usersinfo }
}

// LOCAL GROUPS
func collectGroups(env *Env) func(*Result) {
	var groupsinfo localmachine.Groups
	groups, groupsErr := winapi.ListLocalGroups()
	env.Outcomes["groups/enumerate"] = basedata.CollectionResultFromError(groupsErr)
	for _, group := range groups {
		groupsid, sidErr := winio.LookupSidByName(group.Name)
		env.Outcomes["groups/identity/"+group.Name] = basedata.CollectionResultFromError(sidErr)
		grp := localmachine.Group{
			Name: group.Name,
			SID:  groupsid,
		}
		members, membersErr := winapi.LocalGroupGetMembers(group.Name)
		env.Outcomes["groups/members/"+group.Name] = basedata.CollectionResultFromError(membersErr)
		for _, member := range members {
			grp.Members = append(grp.Members, localmachine.Member{
				Name: member.DomainAndName,
				SID:  member.SID,
			})
		}
		groupsinfo = append(groupsinfo, grp)
	}
	return func(r *Result) { r.Info.Groups = groupsinfo }
}

func collectRegistry(env *Env) func(*Result) {
	registrydata := CollectRegistryItemsWithResults(env.Outcomes)
	return func(r *Result) { r.Info.RegistryData = registrydata }
}

func collectSoftware(env *Env) func(*Result) {
	dumpedsoftwareinfo, softwareErr := winapi.InstalledSoftwareList()
	// The provider does not expose nested enumeration errors. Record only the
	// call outcome, not a claim that the software inventory is complete.
	env.Outcomes["software/provider-call"] = basedata.CollectionResultFromError(softwareErr)
	softwareinfo := make([]localmachine.Software, len(dumpedsoftwareinfo))
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
	if len(softwareinfo) == 0 {
		softwareinfo = nil
	}
	return func(r *Result) { r.Info.Software = softwareinfo }
}

func collectPrivileges(env *Env) func(*Result) {
	var privilegesinfo localmachine.Privileges
	pol, err := LsaOpenPolicy("", _POLICY_LOOKUP_NAMES|_POLICY_VIEW_LOCAL_INFORMATION)
	env.Outcomes["privileges/open"] = basedata.CollectionResultFromError(err)
	if err != nil {
		ui.Warn().Msgf("Could not open LSA policy: %v", err)
		return nil
	}
	defer LsaClose(*pol)
	for _, privilege := range PRIVILEGE_NAMES {
		sids, err := LsaEnumerateAccountsWithUserRight(*pol, string(privilege))
		result := privilegeResult(err)
		env.Outcomes["privileges/assignments/"+string(privilege)] = result
		if err == nil {
			sidstrings := make([]string, len(sids))
			for i, sid := range sids {
				sidstrings[i] = sid.String()
			}
			privilegesinfo = append(privilegesinfo, localmachine.Privilege{
				Name:         string(privilege),
				AssignedSIDs: sidstrings,
			})
		} else if result.Status != basedata.CollectionCollected && result.Status != basedata.CollectionNotFound {
			ui.Warn().Msgf("Problem enumerating %v: %v", privilege, err)
		}
	}
	return func(r *Result) { r.Info.Privileges = privilegesinfo }
}

// LsaEnumerateAccountsWithUserRight reports an empty assignment list as "no
// more items", and a right this Windows version does not define (such as
// SeUnsolicitedInputPrivilege on current releases) as "no such privilege".
func privilegeResult(err error) basedata.CollectionResult {
	switch {
	case err == nil, errors.Is(err, windows.ERROR_NO_MORE_ITEMS), err == STATUS_NO_MORE_ENTRIES, err == NO_MORE_DATA_IS_AVAILABLE:
		return basedata.CollectionResultFromError(nil)
	case errors.Is(err, windows.ERROR_NO_SUCH_PRIVILEGE):
		return basedata.CollectionResult{Status: basedata.CollectionNotFound, ErrorCode: "errno:1313"}
	}
	return basedata.CollectionResultFromError(err)
}
