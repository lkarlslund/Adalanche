package analyze

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var unhandledPrivileges sync.Map

var PrimaryUser = engine.NewAttribute("primaryUser").SetDescription("Derived primary user from local 4624 interactive events")

// Returns the computer object
func ImportCollectorInfo(ao *engine.Objects, cinfo localmachine.Info) (*engine.Object, error) {
	var machine *engine.Object
	var existing bool
	// See if the machine has a unique SID
	localsid, err := windowssecurity.ParseStringSID(cinfo.Machine.LocalSID)
	if err != nil {
		return nil, fmt.Errorf("collected localmachine information for %v doesn't contain valid local machine SID (%v): %v", cinfo.Machine.Name, cinfo.Machine.LocalSID, err)
	}
	var domainsid windowssecurity.SID
	if cinfo.Machine.IsDomainJoined {
		domainsid, err = windowssecurity.ParseStringSID(cinfo.Machine.ComputerDomainSID)
		if cinfo.Machine.ComputerDomainSID != "" && err == nil {
			machine, existing = ao.FindOrAdd(
				analyze.DomainJoinedSID, engine.NewAttributeValueSID(domainsid),
			)
			// It's a duplicate domain member SID :-(
			if existing {
				return nil, fmt.Errorf("duplicate machine info for domain account SID %v found, not loading it. machine names %v and %v", cinfo.Machine.ComputerDomainSID, cinfo.Machine.Name, machine.Label())
			}
			// Link to the AD account
			computer, _ := ao.FindOrAdd(
				activedirectory.ObjectSid, engine.NewAttributeValueSID(domainsid),
			)
			downlevelmachinename := cinfo.Machine.Domain + "\\" + cinfo.Machine.Name + "$"
			computer.SetFlex(
				activedirectory.SAMAccountName, engine.NewAttributeValueString(strings.ToUpper(cinfo.Machine.Name)+"$"),
				engine.DownLevelLogonName, engine.NewAttributeValueString(downlevelmachinename),
			)
			machine.EdgeTo(computer, analyze.EdgeAuthenticatesAs)
			machine.EdgeTo(computer, analyze.EdgeMachineAccount)
			machine.ChildOf(computer)
		}
	} else {
		ui.Debug().Msg("NOT JOINED??")
	}
	if cinfo.UnprivilegedCollection {
		ui.Info().Msgf("Loading partial information from unprivileged collector on machine %v", cinfo.Machine.Name)
	}
	if machine == nil {
		// Not Domain Joined!?
		machine = ao.AddNew()
	}
	machine.SetFlex(
		engine.IgnoreBlanks,
		engine.DisplayName, cinfo.Machine.Name,
		engine.NewAttribute("architecture"), cinfo.Machine.Architecture,
		engine.NewAttribute("editionId"), cinfo.Machine.EditionID,
		engine.NewAttribute("buildBranch"), cinfo.Machine.BuildBranch,
		engine.NewAttribute("buildNumber"), cinfo.Machine.BuildNumber,
		engine.NewAttribute("majorVersionNumber"), cinfo.Machine.MajorVersionNumber,
		engine.NewAttribute("version"), cinfo.Machine.Version,
		engine.NewAttribute("productName"), cinfo.Machine.ProductName,
		engine.NewAttribute("productSuite"), cinfo.Machine.ProductSuite,
		engine.NewAttribute("productType"), cinfo.Machine.ProductType,
		engine.ObjectSid, localsid,
		engine.Type, engine.NewAttributeValueString("Machine"),
		engine.NewAttribute("connectivity"), cinfo.Network.InternetConnectivity,
	)
	if cinfo.Machine.WUServer != "" {
		if u, err := url.Parse(cinfo.Machine.WUServer); err == nil {
			host, _, _ := strings.Cut(u.Host, ":")
			machine.SetFlex(
				WUServer, engine.NewAttributeValueString(host),
			)
		}
	}
	if cinfo.Machine.SCCMLastValidMP != "" {
		if u, err := url.Parse(cinfo.Machine.SCCMLastValidMP); err == nil {
			host, _, _ := strings.Cut(u.Host, ":")
			machine.SetFlex(
				SCCMServer, engine.NewAttributeValueString(host),
			)
		}
	}
	var isdomaincontroller bool
	if cinfo.Machine.ProductType != "" {
		// New way of detecting domain controller
		isdomaincontroller = strings.EqualFold(cinfo.Machine.ProductType, "LANMANNT")
	} else {
		// OK, lets brute force this alien
		for _, group := range cinfo.Groups {
			if group.SID == "S-1-5-32-548" {
				// Account Operators exists only locally on DCs
				isdomaincontroller = true
				break
			}
		}
	}
	if isdomaincontroller {
		ui.Debug().Msgf("Detected %v as local machine data coming from a Domain Controller", cinfo.Machine.Name)
	}
	// Local accounts should not merge, unless we're a DC, then it's OK to merge with the domain source
	uniquesource := engine.NewAttributeValueString(cinfo.Machine.Name)
	// Set source to domain NetBios name if we're a DC
	if isdomaincontroller {
		uniquesource = engine.NewAttributeValueString(cinfo.Machine.Domain)
	}
	ri := relativeInfo{
		LocalName:          engine.NewAttributeValueString(cinfo.Machine.Name),
		DomainName:         engine.NewAttributeValueString(cinfo.Machine.Domain),
		DomainJoinedSID:    domainsid,
		MachineSID:         localsid,
		IsDomainController: isdomaincontroller,
		ao:                 ao,
	}
	// Don't set UniqueSource on the computer object, it needs to merge with the AD object!
	machine.SetFlex(engine.DataSource, uniquesource)
	everyone, _, _ := ri.GetSIDObject(windowssecurity.EveryoneSID, Auto)
	everyone.SetFlex(engine.Type, "Group") // This could go wrong
	everyone.ChildOf(machine)
	authenticatedusers, _, _ := ri.GetSIDObject(windowssecurity.AuthenticatedUsersSID, Auto)
	authenticatedusers.SetFlex(engine.Type, "Group") // This could go wrong
	authenticatedusers.EdgeTo(everyone, activedirectory.EdgeMemberOfGroup)
	authenticatedusers.ChildOf(machine)
	if cinfo.Machine.IsDomainJoined {
		domainauthenticatedusers, _, _ := ri.GetSIDObject(windowssecurity.EveryoneSID, Domain)
		domainauthenticatedusers.EdgeTo(authenticatedusers, activedirectory.EdgeMemberOfGroup)
	}
	var macaddrs, ipaddresses []string
	for _, networkinterface := range cinfo.Network.NetworkInterfaces {
		if strings.Count(networkinterface.MACAddress, ":") == 5 {
			// Sanity check above removes ISATAP interfaces
			if strings.EqualFold(networkinterface.MACAddress, "02:00:4c:4f:4f:50") {
				// Loopback adapter, skip it
				continue
			}
			if strings.EqualFold(networkinterface.MACAddress, "02:50:41:00:00:01") {
				// Palo Alto Protect network interface
				continue
			}
			macaddrs = append(macaddrs, strings.ReplaceAll(networkinterface.MACAddress, ":", ""))
			ipaddresses = append(ipaddresses, networkinterface.Addresses...)
		}
	}
	machine.SetFlex(
		engine.IgnoreBlanks,
		localmachine.MACAddress, macaddrs,
		engine.IPAddress, ipaddresses,
	)
	ao.ReindexObject(machine, false) // We changed stuff after adding it
	// Add local accounts as synthetic objects
	userscontainer := engine.NewObject(activedirectory.Name, "Users")
	ao.Add(userscontainer)
	userscontainer.ChildOf(machine)
	var rdprightshandled bool
	// Privileges to exploits - from https://github.com/gtworek/Priv2Admin
	for _, pi := range cinfo.Privileges {
		var pwn engine.Edge
		switch pi.Name {
		case "SeNetworkLogonRight":
			pwn = EdgeSeNetworkLogonRight
		case "SeRemoteInteractiveLogonRight":
			pwn = EdgeLocalRDPRights
			rdprightshandled = true
		case "SeBackupPrivilege":
			pwn = EdgeSeBackupPrivilege
		case "SeRestorePrivilege":
			pwn = EdgeSeRestorePrivilege
		case "SeAssignPrimaryTokenPrivilege":
			pwn = EdgeSeAssignPrimaryToken
		case "SeCreateTokenPrivilege":
			pwn = EdgeSeCreateToken
		case "SeDebugPrivilege":
			pwn = EdgeSeDebug
		case "SeImpersonatePrivilege":
			pwn = EdgeSeImpersonate
		case "SeLoadDriverPrivilege":
			pwn = EdgeSeLoadDriver
		case "SeManageVolumePrivilege":
			pwn = EdgeSeManageVolume
		case "SeTakeOwnershipPrivilege":
			pwn = EdgeSeTakeOwnership
		case "SeTrustedCredManAccess":
			pwn = EdgeSeTrustedCredManAccess
		case "SeMachineAccountPrivilege":
		// Join machine to domain
		// pwn = EdgeSeMachineAccount
		case "SeTcbPrivilege":
			pwn = EdgeSeTcb
		case "SeIncreaseQuotaPrivilege",
			"SeSystemProfilePrivilege",
			"SeSecurityPrivilege",
			"SeSystemtimePrivilege",
			"SeProfileSingleProcessPrivilege",
			"SeIncreaseBasePriorityPrivilege",
			"SeCreatePagefilePrivilege",
			"SeShutdownPrivilege",
			"SeAuditPrivilege",
			"SeSystemEnvironmentPrivilege",
			"SeChangeNotifyPrivilege",
			"SeRemoteShutdownPrivilege",
			"SeUndockPrivilege",
			"SeCreateGlobalPrivilege",
			"SeIncreaseWorkingSetPrivilege",
			"SeTimeZonePrivilege",
			"SeCreateSymbolicLinkPrivilege",
			"SeInteractiveLogonRight",
			"SeDenyInteractiveLogonRight",
			"SeDenyRemoteInteractiveLogonRight",
			"SeBatchLogonRight",
			"SeServiceLogonRight",
			"SeDelegateSessionUserImpersonatePrivilege",
			"SeLockMemoryPrivilege",
			"SeTrustedCredManAccessPrivilege",
			"SeDenyNetworkLogonRight",
			"SeDenyBatchLogonRight",
			"SeDenyServiceLogonRight",
			"SeRelabelPrivilege",
			"SeCreatePermanentPrivilege":
			// No edge
			continue
		case "SeEnableDelegationPrivilege":
			ui.Trace().Msgf("SeEnableDelegationPrivilege hit")
			continue
		default:
			_, loaded := unhandledPrivileges.LoadOrStore(pi, struct{}{})
			if !loaded {
				ui.Warn().Msgf("Unhandled privilege encountered; %v", pi)
			}
			continue
		}
		for _, sidstring := range pi.AssignedSIDs {
			sid, err := windowssecurity.ParseStringSID(sidstring)
			if err != nil {
				ui.Error().Msgf("Invalid SID %v: %v", sidstring, err)
				continue
			}
			// Potential translation
			assignee, _, _ := ri.GetSIDObject(sid, Auto)
			assignee.EdgeTo(machine, pwn)
		}
	}
	if !isdomaincontroller {
		for _, user := range cinfo.Users {
			uac := 512
			if !user.IsEnabled {
				uac += engine.UAC_ACCOUNTDISABLE
			}
			if user.IsLocked {
				uac += engine.UAC_LOCKOUT
			}
			if user.PasswordNeverExpires {
				uac += engine.UAC_DONT_EXPIRE_PASSWORD
			}
			if user.NoChangePassword {
				uac += engine.UAC_PASSWD_CANT_CHANGE
			}
			usid, err := windowssecurity.ParseStringSID(user.SID)
			if err == nil {
				uo := ao.AddNew(
					engine.IgnoreBlanks,
					activedirectory.ObjectSid, engine.NewAttributeValueSID(usid),
					activedirectory.Type, "Person",
					activedirectory.DisplayName, user.FullName,
					activedirectory.Name, user.Name,
					activedirectory.UserAccountControl, uac,
					activedirectory.PwdLastSet, user.PasswordLastSet,
					activedirectory.LastLogon, user.LastLogon,
					engine.DownLevelLogonName, cinfo.Machine.Name+"\\"+user.Name,
					activedirectory.BadPwdCount, user.BadPasswordCount,
					activedirectory.LogonCount, user.NumberOfLogins,
					engine.DataSource, uniquesource,
				)
				uo.ChildOf(userscontainer)
				uo.EdgeTo(authenticatedusers, activedirectory.EdgeMemberOfGroup)

				if user.IsEnabled {
					uo.Tag("account_enabled")
				} else {
					uo.Tag("account_disabled")
				}
				if user.IsLocked {
					uo.Tag("account_locked")
				}
				if user.NoChangePassword {
					uo.Tag("password_cant_change")
				}
				if user.PasswordNeverExpires {
					uo.Tag("password_never_expires")
				}
			} else {
				ui.Warn().Msgf("Invalid user SID in dump: %v", user.SID)
			}
		}
		// Iterate over Groups
		groupscontainer := engine.NewObject(activedirectory.Name, "Groups")
		ao.Add(groupscontainer)
		groupscontainer.ChildOf(machine)
		for _, group := range cinfo.Groups {
			groupsid, err := windowssecurity.ParseStringSID(group.SID)
			// Potential translation
			groupobject := ao.AddNew(
				engine.IgnoreBlanks,
				activedirectory.ObjectSid, engine.NewAttributeValueSID(groupsid),
				activedirectory.Name, group.Name,
				activedirectory.Description, group.Comment,
				engine.Type, "Group",
				engine.DataSource, uniquesource,
			)
			groupobject.ChildOf(groupscontainer)
			if err != nil && group.Name != "SMS Admins" {
				ui.Warn().Msgf("Can't convert local group SID %v: %v", group.SID, err)
				continue
			}
			for _, member := range group.Members {
				var membersid windowssecurity.SID
				if member.SID != "" {
					membersid, err = windowssecurity.ParseStringSID(member.SID)
					if err != nil {
						ui.Warn().Msgf("Can't convert local group member SID %v: %v", member.SID, err)
						continue
					}
				} else {
					// Some members show up with the SID in the name field FME
					membersid, err = windowssecurity.ParseStringSID(member.Name)
					if err != nil {
						ui.Info().Msgf("Fallback SID translation on %v failed: %v", member.Name, err)
						continue
					}
				}
				memberobject, existing, local := ri.GetSIDObject(membersid, Auto)
				// Collector sometimes returns junk, but if we have downlevel logon name we store it
				if member.Name != "" && !strings.HasSuffix(member.Name, "\\") && !strings.HasPrefix(member.Name, "S-1-") {
					memberobject.SetFlex(
						engine.DownLevelLogonName, member.Name,
					)
				}
				memberobject.EdgeTo(groupobject, activedirectory.EdgeMemberOfGroup)
				switch {
				case group.Name == "SMS Admins":
					groupobject.EdgeTo(machine, EdgeLocalSMSAdmins)
				case groupsid == windowssecurity.AdministratorsSID:
					groupobject.EdgeTo(machine, EdgeLocalAdminRights)
				case groupsid == windowssecurity.DCOMUsersSID:
					groupobject.EdgeTo(machine, EdgeLocalDCOMRights)
				case groupsid == windowssecurity.RemoteDesktopUsersSID:
					if !rdprightshandled {
						groupobject.EdgeTo(machine, EdgeLocalRDPRights)
					}
				}
				if local && !existing {
					// Maybe a deleted user or group
					memberobject.ChildOf(machine)
				}
			}
		}
	}

	// USERS THAT HAVE SESSIONS ON THE MACHINE ONCE IN WHILE
	topInteractiveUsers := map[string]int{}
	for _, login := range cinfo.LoginInfos {
		usersid, err := windowssecurity.ParseStringSID(login.SID)
		if err != nil {
			ui.Warn().Msgf("Can't convert local user SID %v: %v", login.SID, err)
			continue
		}
		if usersid.Component(2) != 21 {
			continue // Not a local or domain SID, skip it
		}
		// Potential translation
		// usersid = MapSID(originalsid, localsid, usersid)
		user := ao.AddNew(
			activedirectory.ObjectSid, engine.NewAttributeValueSID(usersid),
			engine.Type, "Person",
		)
		if usersid.StripRID() == localsid || usersid.Component(2) != 21 {
			user.SetFlex(
				engine.DataSource, uniquesource,
			)
		}
		var username string
		if !strings.Contains(login.Domain, ".") {
			username = login.Domain + "\\" + login.User
			user.Set(engine.DownLevelLogonName, engine.NewAttributeValueString(username))
		} else {
			// user.Set(engine.SAMAccountName, engine.NewAttributeValueString(login.User))
			username = login.User + "@" + login.Domain
			user.Set(engine.UserPrincipalName, engine.NewAttributeValueString(username))
		}

		if login.LogonType == 2 || login.LogonType == 11 {
			logins := topInteractiveUsers[username]
			logins++
			topInteractiveUsers[username] = logins
		}

		// loginSince := login.LastSeen.Sub(cinfo.Collected).Hours() / 24
		// switch {
		// case loginSince <= 1:
		// 	machine.EdgeTo(user, EdgeLocalSessionLastDay)
		// case loginSince <= 7:
		// 	machine.EdgeTo(user, EdgeLocalSessionLastWeek)
		// case loginSince <= 31:
		// 	machine.EdgeTo(user, EdgeLocalSessionLastMonth)
		// }

		// Parse event id 4624
		switch login.LogonType {
		case 2, 11: // Interactive or cached interactive
			machine.EdgeTo(user, EdgeSessionLocal)
		case 3: // Network
			machine.EdgeTo(user, EdgeSessionNetwork)
			switch login.AuthenticationPackageName {
			case "NTLM":
				machine.EdgeTo(user, EdgeSessionNetworkNTLM)
			case "NTLM V2":
				machine.EdgeTo(user, EdgeSessionNetworkNTLMv2)
			case "Kerberos":
				machine.EdgeTo(user, EdgeSessionNetworkKerberos)
			case "Negotiate":
				machine.EdgeTo(user, EdgeSessionNetworkNegotiate)
			default:
				ui.Debug().Msgf("Other: %v", login.AuthenticationPackageName)
			}
		case 4: // Batch (scheduled task)
			machine.EdgeTo(user, EdgeSessionBatch)
		case 5: // Service
			machine.EdgeTo(user, EdgeSessionService)
		case 10: // RDP
			machine.EdgeTo(user, EdgeSessionRDP)
		}
		machine.EdgeTo(user, EdgeSession)

		for _, ipaddress := range login.IpAddress {
			IpMachine := ao.AddNew(
				engine.IPAddress, engine.NewAttributeValueString(ipaddress),
				engine.Type, "Machine",
			)
			IpMachine.EdgeTo(user, EdgeSession)
		}
	}
	if len(topInteractiveUsers) > 0 {
		var primaryuser string
		var maxcount int
		for user, count := range topInteractiveUsers {
			if count > maxcount {
				maxcount = count
				primaryuser = user
			}
		}
		if primaryuser != "" {
			machine.Set(PrimaryUser, engine.NewAttributeValueString(primaryuser))
		}
	}

	// AUTOLOGIN CREDENTIALS - ONLY IF DOMAIN JOINED AND IT'S TO THIS DOMAIN
	if cinfo.Machine.DefaultUsername != "" &&
		cinfo.Machine.DefaultDomain != "" &&
		strings.EqualFold(cinfo.Machine.DefaultDomain, cinfo.Machine.Domain) {
		// NETBIOS name for domain check FIXME
		user, _ := ao.FindOrAdd(
			engine.NetbiosDomain, engine.NewAttributeValueString(cinfo.Machine.DefaultDomain),
			activedirectory.SAMAccountName, cinfo.Machine.DefaultUsername,
			engine.DownLevelLogonName, cinfo.Machine.DefaultDomain+"\\"+cinfo.Machine.DefaultUsername,
			activedirectory.Type, "Person",
		)
		machine.EdgeTo(user, EdgeHasAutoAdminLogonCredentials)
	}
	// SERVICES
	servicescontainer := engine.NewObject(activedirectory.Name, "Services")
	ao.Add(servicescontainer)
	servicescontainer.ChildOf(machine)
	// All services are a member of this group
	localservicesgroup := ao.AddNew(
		activedirectory.ObjectSid, engine.NewAttributeValueSID(windowssecurity.ServicesSID),
		engine.DownLevelLogonName, cinfo.Machine.Name+"\\Services",
		engine.DisplayName, "Services (local)",
		engine.DataSource, cinfo.Machine.Name,
		engine.Type, "Group",
	)
	localservicesgroup.ChildOf(machine)
	for _, service := range cinfo.Services {
		serviceobject := engine.NewObject(
			engine.IgnoreBlanks,
			activedirectory.Name, service.Name,
			activedirectory.DisplayName, service.Name,
			activedirectory.Description, service.Description,
			ServiceStart, int64(service.Start),
			ServiceType, int64(service.Type),
			activedirectory.Type, "Service",
		)
		if service.Start < 3 {
			serviceobject.Tag("service_autostart")
		}
		switch service.Start {
		case 0:
			serviceobject.Tag("service_boot")
		case 1:
			serviceobject.Tag("service_system")
		case 2:
			serviceobject.Tag("service_automatic")
		case 3:
			serviceobject.Tag("service_manual")
		case 4:
			serviceobject.Tag("service_disabled")
		}
		ao.Add(serviceobject)
		serviceobject.ChildOf(servicescontainer)
		serviceobject.EdgeTo(localservicesgroup, EdgeMemberOfGroup)
		machine.EdgeTo(serviceobject, EdgeHosts)
		var serviceaccountSID windowssecurity.SID
		// If we have the SID use that
		if service.AccountSID != "" {
			serviceaccountSID, err = windowssecurity.ParseStringSID(service.AccountSID)
			if err != nil {
				ui.Warn().Msgf("Service account SID (%v) parsing problem: %v", service.AccountSID, err)
			}
		}
		// Some service don't have SID, just the name
		if serviceaccountSID.IsBlank() {
			if strings.EqualFold(service.Account, "LocalSystem") {
				serviceaccountSID = windowssecurity.SystemSID
			}
		}
		var svcaccount *engine.Object
		if !serviceaccountSID.IsBlank() {
			svcaccount = ao.AddNew(
				activedirectory.ObjectSid, engine.NewAttributeValueSID(serviceaccountSID),
			)
			if serviceaccountSID.StripRID() == localsid || serviceaccountSID.Component(2) != 21 {
				svcaccount.SetFlex(
					engine.DataSource, uniquesource,
				)
				nameparts := strings.Split(service.Account, "\\")
				if len(nameparts) == 2 && strings.EqualFold(nameparts[0], cinfo.Machine.Domain) {
					svcaccount.SetFlex(
						engine.DownLevelLogonName, service.Account,
					)
				}
				svcaccount.ChildOf(serviceobject)
			}
			if serviceaccountSID.Component(2) < 21 {
				svcaccount.SetFlex(activedirectory.Type, "Group")
			}
		}
		if svcaccount == nil {
			if service.Account != "" {
				nameparts := strings.Split(service.Account, "\\")
				// account can be USER, .\USER, DOMAIN\USER (come on!)
				if len(nameparts) == 2 {
					if nameparts[0] == "." || strings.EqualFold(nameparts[0], cinfo.Machine.Domain) {
						// .\Name or MACHINE\Name
						svcaccount, _ = ao.FindOrAdd(
							engine.DownLevelLogonName, engine.NewAttributeValueString(cinfo.Machine.Domain+"\\"+nameparts[1]),
						)
						svcaccount.SetFlex(engine.DataSource, uniquesource)
					} else {
						// DOMAIN\Name
						svcaccount, _ = ao.FindOrAdd(
							engine.DownLevelLogonName, engine.NewAttributeValueString(service.Account),
						)
					}
				} else if len(nameparts) == 1 {
					// no \\ in name, just a user name!? this COULD be wrong, might be a DOMAIN account?
					svcaccount, _ = ao.FindOrAdd(
						engine.DownLevelLogonName, engine.NewAttributeValueString(cinfo.Machine.Domain+"\\"+nameparts[0]),
					)
				}
			}
		}
		// Did we somehow manage to find an account?
		if svcaccount != nil {
			if serviceaccountSID.Component(2) == 21 || serviceaccountSID.Component(2) == 32 {
				// Foreign to computer, so it gets a direct edge
				machine.EdgeTo(svcaccount, EdgeHasServiceAccountCredentials)
			}
			if serviceaccountSID != windowssecurity.LocalServiceSID {
				serviceobject.EdgeTo(svcaccount, analyze.EdgeAuthenticatesAs)
			}
		} else if service.Account != "" || service.AccountSID != "" {
			ui.Warn().Msgf("Unhandled service credentials %+v", service)
		}
		// Specific service SID
		so := ao.FindOrAddSID(windowssecurity.ServiceNameToServiceSID(service.Name))
		// ui.Debug().Msgf("Added service account %v for service %v", so.SID().String(), service.Name)
		so.SetFlex(
			activedirectory.Name, engine.NewAttributeValueString("Service account for "+service.Name),
		)
		serviceobject.EdgeTo(so, analyze.EdgeAuthenticatesAs)
		// Change service executable via registry
		if service.RegistryOwner != "" {
			ro, err := windowssecurity.ParseStringSID(service.RegistryOwner)
			if err == nil {
				o := ao.AddNew(
					activedirectory.ObjectSid, engine.NewAttributeValueSID(ro),
				)
				if ro.StripRID() == localsid || ro.Component(2) != 21 {
					o.SetFlex(
						engine.DataSource, uniquesource,
					)
				}
				o.EdgeTo(serviceobject, EdgeRegistryOwns)
			}
		}
		if sd, err := engine.ParseACL(service.RegistryDACL); err == nil {
			for _, entry := range sd.Entries {
				entrysid := entry.SID
				if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entry.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE) == 0 {
					if entrysid == windowssecurity.AdministratorsSID || entrysid == windowssecurity.SystemSID || entrysid.Component(2) == 80 /* Service user */ {
						// if we have local admin it's already game over so don't map this
						continue
					}
					var o *engine.Object
					if entrysid == windowssecurity.SystemSID {
						o = machine
					} else {
						o = ao.AddNew(
							activedirectory.ObjectSid, engine.NewAttributeValueSID(entrysid),
						)
						if entrysid != windowssecurity.EveryoneSID && (entrysid.StripRID() == localsid || entrysid.Component(2) != 21) {
							o.SetFlex(
								engine.DataSource, uniquesource,
							)
						}
					}
					if entry.Mask&engine.KEY_SET_VALUE != 0 {
						o.EdgeTo(serviceobject, EdgeRegistryWrite)
					}
					if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
						o.EdgeTo(serviceobject, EdgeRegistryModifyDACL)
					}
					if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
						o.EdgeTo(serviceobject, activedirectory.EdgeTakeOwnership)
					}
				}
			}
		}
		// Change service executable contents
		serviceimageobject := engine.NewObject(
			activedirectory.DisplayName, filepath.Base(service.ImageExecutable),
			AbsolutePath, service.ImageExecutable,
			engine.Type, "Executable",
		)
		ao.Add(serviceimageobject)
		serviceimageobject.EdgeTo(serviceobject, EdgeExecuted)
		serviceimageobject.ChildOf(serviceobject)
		if ownersid, err := windowssecurity.ParseStringSID(service.ImageExecutableOwner); err == nil {
			// Potential translation
			if ownersid.Component(2) == 80 /* Service user */ {
				continue
			}
			owner := ao.AddNew(
				activedirectory.ObjectSid, engine.NewAttributeValueSID(ownersid),
			)
			if ownersid.StripRID() == localsid || ownersid.Component(2) != 21 {
				owner.SetFlex(
					engine.DataSource, uniquesource,
				)
			}
			owner.EdgeTo(serviceimageobject, activedirectory.EdgeOwns)
		}
		if sd, err := engine.ParseACL(service.ImageExecutableDACL); err == nil {
			for _, entry := range sd.Entries {
				entrysid := entry.SID
				if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entrysid.Component(2) == 21 || entry.SID == windowssecurity.EveryoneSID || entry.SID == windowssecurity.AuthenticatedUsersSID) {
					o := ao.AddNew(
						activedirectory.ObjectSid, engine.NewAttributeValueSID(entrysid),
					)
					if entrysid.StripRID() == localsid || entrysid.Component(2) != 21 {
						o.SetFlex(
							engine.DataSource, uniquesource,
						)
					}
					if entry.Mask&engine.FILE_WRITE_DATA != 0 {
						o.EdgeTo(serviceimageobject, EdgeFileWrite)
					}
					if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
						o.EdgeTo(serviceimageobject, activedirectory.EdgeTakeOwnership) // Not sure about this one
					}
					if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
						o.EdgeTo(serviceimageobject, activedirectory.EdgeWriteDACL)
					}
				}
			}
			// ui.Debug().Msgf("Service %v executable %v: %v", service.Name, service.ImageExecutable, sd)
		}
	}
	// SOFTWARE INVENTORY AS ATTRIBUTES
	installedsoftware := make([]string, len(cinfo.Software))
	for i, software := range cinfo.Software {
		installedsoftware[i] = fmt.Sprintf(
			"%v %v %v", software.Publisher, software.DisplayName, software.DisplayVersion,
		)
	}
	if len(installedsoftware) > 0 {
		machine.SetFlex(localmachine.InstalledSoftware, installedsoftware)
	}
	// SHARES
	if len(cinfo.Shares) > 0 {
		computershares := ao.AddNew(
			activedirectory.Type, "Container",
			activedirectory.DisplayName, "Shares",
		)
		computershares.ChildOf(machine)
		for _, share := range cinfo.Shares {
			shareobject := ao.AddNew(
				engine.IgnoreBlanks,
				activedirectory.DisplayName, "\\\\"+cinfo.Machine.Name+"\\"+share.Name,
				AbsolutePath, share.Path,
				engine.Description, share.Remark,
				ShareType, share.Type,
				engine.Type, "Share",
			)
			machine.EdgeTo(shareobject, EdgeShares)
			shareobject.ChildOf(computershares)
			// Fileshare rights
			if len(share.DACL) == 0 {
				ui.Warn().Msgf("No security descriptor for machine %v file share %v", cinfo.Machine.Name, share.Name)
			} else if sd, err := engine.CacheOrParseSecurityDescriptor(string(share.DACL)); err == nil {
				// if !sd.Owner.IsNull() {
				// 	ui.Warn().Msgf("Share %v has owner set to %v", share.Name, sd.Owner)
				// }
				// if !sd.Group.IsNull() {
				// 	ui.Warn().Msgf("Share %v has group set to %v", share.Name, sd.Group)
				// }
				for _, entry := range sd.DACL.Entries {
					if entry.Type == engine.ACETYPE_ACCESS_ALLOWED {
						entrysid := entry.SID
						o, _, _ := ri.GetSIDObject(entrysid, Auto)
						if entry.Mask&engine.FILE_READ_DATA != 0 {
							o.EdgeTo(shareobject, EdgeFileRead)
						}
						if entry.Mask&engine.FILE_WRITE_DATA != 0 {
							o.EdgeTo(shareobject, EdgeFileWrite)
						}
						if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
							o.EdgeTo(shareobject, activedirectory.EdgeTakeOwnership) // Not sure about this one
						}
						if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
							o.EdgeTo(shareobject, activedirectory.EdgeWriteDACL)
						}
					} else if entry.Type == engine.ACETYPE_ACCESS_ALLOWED_OBJECT {
						ui.Debug().Msg("Fixme")
					}
				}
			} else {
				ui.Warn().Msgf("Could not parse machine %v file share %v security descriptor", cinfo.Machine.Name, share.Name)
			}
			pathobject := ao.AddNew(
				engine.IgnoreBlanks,
				activedirectory.DisplayName, share.Path,
				AbsolutePath, share.Path,
				engine.Type, "Directory",
			)
			pathobject.ChildOf(machine)
			shareobject.EdgeTo(pathobject, EdgePublishes)
			// File rights
			if sd, err := engine.CacheOrParseSecurityDescriptor(string(share.PathDACL)); err == nil {
				if !sd.Owner.IsNull() {
					owner := ao.AddNew(
						activedirectory.ObjectSid, engine.NewAttributeValueSID(sd.Owner),
					)
					if sd.Owner.StripRID() == localsid || sd.Owner.Component(2) != 21 {
						owner.SetFlex(
							engine.DataSource, uniquesource,
						)
					}
					owner.EdgeTo(pathobject, activedirectory.EdgeOwns)
				}
				for _, entry := range sd.DACL.Entries {
					entrysid := entry.SID
					if entry.Type == engine.ACETYPE_ACCESS_ALLOWED {
						aclsid := ao.AddNew(
							activedirectory.ObjectSid, engine.NewAttributeValueSID(entrysid),
						)
						if entrysid.StripRID() == localsid || entrysid.Component(2) != 21 {
							aclsid.SetFlex(
								engine.DataSource, uniquesource,
							)
						}
						if entry.Mask&engine.FILE_READ_DATA != 0 {
							aclsid.EdgeTo(pathobject, EdgeFileRead)
						}
						if entry.Mask&engine.FILE_WRITE_DATA != 0 {
							aclsid.EdgeTo(pathobject, EdgeFileWrite)
						}
						if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
							aclsid.EdgeTo(pathobject, activedirectory.EdgeTakeOwnership) // Not sure about this one
						}
						if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
							aclsid.EdgeTo(pathobject, activedirectory.EdgeWriteDACL)
						}
					} else if entry.Type == engine.ACETYPE_ACCESS_ALLOWED_OBJECT {
						ui.Debug().Msgf("Fixme")
					}
				}
			}
		}
	}
	// Everyone / World and Authenticated Users merge with Domain - not pretty IMO
	if cinfo.Machine.IsDomainJoined && !isdomaincontroller {
		domaineveryoneobject := ao.AddNew(
			activedirectory.ObjectSid, engine.NewAttributeValueSID(windowssecurity.EveryoneSID),
			engine.DataSource, engine.NewAttributeValueString(cinfo.Machine.Domain),
		)
		// Everyone who is a member of the Domain is also a member of "our" Everyone
		domaineveryoneobject.EdgeTo(everyone, activedirectory.EdgeMemberOfGroup)
		domainauthenticatedusers := ao.AddNew(
			activedirectory.ObjectSid, engine.NewAttributeValueSID(windowssecurity.AuthenticatedUsersSID),
			engine.DataSource, engine.NewAttributeValueString(cinfo.Machine.Domain),
		)
		domainauthenticatedusers.EdgeTo(authenticatedusers, activedirectory.EdgeMemberOfGroup)
	}
	return machine, nil
}

type relativeInfo struct {
	LocalName          engine.AttributeValue
	DomainName         engine.AttributeValue
	ao                 *engine.Objects
	MachineSID         windowssecurity.SID
	DomainJoinedSID    windowssecurity.SID
	IsDomainController bool
}
type RelativeLocation byte

const (
	Auto RelativeLocation = iota
	Local
	Domain
)

func (ri *relativeInfo) GetSIDObject(targetSID windowssecurity.SID, location RelativeLocation) (result *engine.Object, existing bool, local bool) {
	dataSource := ri.LocalName
	local = true
	switch location {
	case Local:
		// dataSource is already local name
	case Domain:
		dataSource = ri.DomainName
		local = false
	case Auto:
		if ri.IsDomainController {
			dataSource = ri.DomainName
			local = false
		} else if targetSID.Component(2) == 21 && targetSID.StripRID() != ri.MachineSID {
			// Universally identifiable, just go with that and let merge fix it
			assignee, existing := ri.ao.FindOrAdd(
				activedirectory.ObjectSid, engine.NewAttributeValueSID(targetSID),
			)
			return assignee, existing, false
		}
	}
	assignee, existing := ri.ao.FindTwoOrAdd(
		activedirectory.ObjectSid, engine.NewAttributeValueSID(targetSID),
		engine.DataSource, dataSource,
	)
	return assignee, existing, local
}
