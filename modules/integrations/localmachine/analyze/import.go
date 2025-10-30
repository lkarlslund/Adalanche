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

const (
	TASK_LOGON_NONE                          int = iota // the logon method is not specified. Used for non-NT credentials
	TASK_LOGON_PASSWORD                                 // use a password for logging on the user. The password must be supplied at registration time
	TASK_LOGON_S4U                                      // the service will log the user on using Service For User (S4U), and the task will run in a non-interactive desktop. When an S4U logon is used, no password is stored by the system and there is no access to either the network or to encrypted files
	TASK_LOGON_INTERACTIVE_TOKEN                        // user must already be logged on. The task will be run only in an existing interactive session
	TASK_LOGON_GROUP                                    // group activation
	TASK_LOGON_SERVICE_ACCOUNT                          // indicates that a Local System, Local Service, or Network Service account is being used as a security context to run the task
	TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD            // first use the interactive token. If the user is not logged on (no interactive token is available), then the password is used. The password must be specified when a task is registered. This flag is not recommended for new tasks because it is less reliable than TASK_LOGON_PASSWORD
)

// Returns the computer object
func ImportCollectorInfo(ao *engine.IndexedGraph, cinfo localmachine.Info) (*engine.Node, error) {
	var machine *engine.Node
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
				analyze.DomainJoinedSID, engine.NV(domainsid),
			)
			// It's a duplicate domain member SID :-(
			if existing {
				return nil, fmt.Errorf("duplicate machine info for domain account SID %v found, not loading it. machine names %v and %v", cinfo.Machine.ComputerDomainSID, cinfo.Machine.Name, machine.Label())
			}
			// Link to the AD account
			computer, _ := ao.FindOrAdd(
				activedirectory.ObjectSid, engine.NV(domainsid),
			)
			downlevelmachinename := cinfo.Machine.Domain + "\\" + cinfo.Machine.Name + "$"
			computer.SetFlex(
				activedirectory.SAMAccountName, engine.NV(strings.ToUpper(cinfo.Machine.Name)+"$"),
				engine.DownLevelLogonName, engine.NV(downlevelmachinename),
			)
			ao.EdgeTo(machine, computer, analyze.EdgeAuthenticatesAs)
			ao.EdgeTo(machine, computer, analyze.EdgeMachineAccount)
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
		engine.NewAttribute("displayVersion"), cinfo.Machine.DisplayVersion,
		engine.NewAttribute("buildLab"), cinfo.Machine.BuildLab,
		engine.NewAttribute("lcuVer"), cinfo.Machine.LCUVer,
		engine.ObjectSid, localsid,
		engine.Type, engine.NV("Machine"),
		engine.NewAttribute("connectivity"), cinfo.Network.InternetConnectivity,
	)
	if cinfo.Machine.WUServer != "" {
		if u, err := url.Parse(cinfo.Machine.WUServer); err == nil {
			host, _, _ := strings.Cut(u.Host, ":")
			machine.SetFlex(
				WUServer, engine.NV(host),
			)
		}
	}
	if cinfo.Machine.SCCMLastValidMP != "" {
		if u, err := url.Parse(cinfo.Machine.SCCMLastValidMP); err == nil {
			host, _, _ := strings.Cut(u.Host, ":")
			machine.SetFlex(
				SCCMServer, engine.NV(host),
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
	uniquesource := engine.NV(cinfo.Machine.Name)
	// Set source to domain NetBios name if we're a DC
	if isdomaincontroller {
		uniquesource = engine.NV(cinfo.Machine.Domain)
	}

	// ri := relativeInfo{
	// 	LocalName:          engine.NV(cinfo.Machine.Name),
	// 	DomainName:         engine.NV(cinfo.Machine.Domain),
	// 	DomainJoinedSID:    domainsid,
	// 	MachineSID:         localsid,
	// 	IsDomainController: isdomaincontroller,
	// 	ao:                 ao,
	// }

	// Don't set UniqueSource on the computer object, it needs to merge with the AD object!
	machine.SetFlex(engine.DataSource, uniquesource)
	everyone := ao.FindOrAddAdjacentSID(windowssecurity.EveryoneSID, machine)
	everyone.SetFlex(engine.Type, "Group") // This could go wrong
	everyone.ChildOf(machine)
	authenticatedUsers := ao.FindOrAddAdjacentSID(windowssecurity.AuthenticatedUsersSID, machine)
	authenticatedUsers.SetFlex(engine.Type, "Group") // This could go wrong
	ao.EdgeTo(authenticatedUsers, everyone, activedirectory.EdgeMemberOfGroup)
	authenticatedUsers.ChildOf(machine)
	if cinfo.Machine.IsDomainJoined {
		domainauthenticatedusers, _ := ao.FindTwoOrAdd(
			engine.ObjectSid, engine.NV(windowssecurity.EveryoneSID),
			engine.DataSource, engine.NV(cinfo.Machine.Domain),
		)
		ao.EdgeTo(domainauthenticatedusers, authenticatedUsers, activedirectory.EdgeMemberOfGroup)
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
	userscontainer := engine.NewNode(activedirectory.Name, "Users")
	ao.Add(userscontainer)
	userscontainer.ChildOf(machine)
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
				localUser := ao.AddNew(
					engine.IgnoreBlanks,
					activedirectory.ObjectSid, engine.NV(usid),
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
				localUser.ChildOf(userscontainer)
				ao.EdgeTo(localUser, authenticatedUsers, activedirectory.EdgeMemberOfGroup)

				if user.IsEnabled {
					localUser.Tag("account_enabled")
				} else {
					localUser.Tag("account_disabled")
				}
				if user.IsLocked {
					localUser.Tag("account_locked")
				}
				if user.NoChangePassword {
					localUser.Tag("password_cant_change")
				}
				if user.PasswordNeverExpires {
					localUser.Tag("password_never_expires")
				}
			} else {
				ui.Warn().Msgf("Invalid user SID in dump: %v", user.SID)
			}
		}
		// Iterate over Groups
		groupscontainer := engine.NewNode(activedirectory.Name, "Groups")
		ao.Add(groupscontainer)
		groupscontainer.ChildOf(machine)
		for _, group := range cinfo.Groups {
			groupsid, err := windowssecurity.ParseStringSID(group.SID)
			if err != nil {
				ui.Warn().Msgf("Can't convert local group SID %v: %v", group.SID, err)
				continue
			}
			// Potential translation
			localGroup := ao.AddNew(
				engine.IgnoreBlanks,
				activedirectory.ObjectSid, engine.NV(groupsid),
				activedirectory.Name, group.Name,
				activedirectory.Description, group.Comment,
				engine.Type, "Group",
				engine.DataSource, uniquesource,
			)
			localGroup.ChildOf(groupscontainer)
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
				memberobject := ao.FindOrAddAdjacentSID(membersid, machine)
				// Collector sometimes returns junk, but if we have downlevel logon name we store it
				if member.Name != "" && !strings.HasSuffix(member.Name, "\\") && !strings.HasPrefix(member.Name, "S-1-") {
					memberobject.SetFlex(
						engine.DownLevelLogonName, member.Name,
					)
				}
				ao.EdgeTo(memberobject, localGroup, activedirectory.EdgeMemberOfGroup)
				switch {
				case group.Name == "SMS Admins":
					ao.EdgeTo(localGroup, machine, EdgeLocalSMSAdmins)
				case groupsid == windowssecurity.AdministratorsSID:
					ao.EdgeTo(localGroup, machine, EdgeLocalAdminRights)
				case groupsid == windowssecurity.DCOMUsersSID:
					ao.EdgeTo(localGroup, machine, EdgeLocalDCOMRights)
				case groupsid == windowssecurity.RemoteDesktopUsersSID:
					ao.EdgeTo(localGroup, machine, EdgeLocalRDPRights)
				}
				if memberobject.HasAttr(engine.DataSource) && !existing {
					// Maybe a deleted user or group
					if memberobject.Parent() == nil {
						memberobject.ChildOf(machine)
					}
				}
			}
		}
	}

	// Privileges to exploits - from https://github.com/gtworek/Priv2Admin
	for _, pi := range cinfo.Privileges {
		var edge engine.Edge
		switch pi.Name {
		case "SeNetworkLogonRight":
			edge = EdgeSeNetworkLogonRight
		case "SeRemoteInteractiveLogonRight":
			edge = EdgeLocalRDPRights
		case "SeBackupPrivilege":
			edge = EdgeSeBackupPrivilege
		case "SeRestorePrivilege":
			edge = EdgeSeRestorePrivilege
		case "SeAssignPrimaryTokenPrivilege":
			edge = EdgeSeAssignPrimaryToken
		case "SeCreateTokenPrivilege":
			edge = EdgeSeCreateToken
		case "SeDebugPrivilege":
			edge = EdgeSeDebug
		case "SeImpersonatePrivilege":
			edge = EdgeSeImpersonate
		case "SeLoadDriverPrivilege":
			edge = EdgeSeLoadDriver
		case "SeManageVolumePrivilege":
			edge = EdgeSeManageVolume
		case "SeTakeOwnershipPrivilege":
			edge = EdgeSeTakeOwnership
		case "SeTrustedCredManAccess":
			edge = EdgeSeTrustedCredManAccess
		case "SeMachineAccountPrivilege":
		// Join machine to domain
		// pwn = EdgeSeMachineAccount
		case "SeTcbPrivilege":
			edge = EdgeSeTcb
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
			assignee := ao.FindOrAddAdjacentSID(sid, machine)
			ao.EdgeTo(assignee, machine, edge)
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
		loggedin := ao.FindOrAddAdjacentSID(usersid, machine)
		if usersid.StripRID() == localsid || usersid.Component(2) != 21 {
			loggedin.SetFlex(
				engine.DataSource, uniquesource,
			)
		}
		var username string
		if !strings.Contains(login.Domain, ".") {
			username = login.Domain + "\\" + login.User
			loggedin.Set(engine.DownLevelLogonName, engine.NV(username))
		} else {
			// user.Set(engine.SAMAccountName, engine.NewAttributeValueString(login.User))
			username = login.User + "@" + login.Domain
			loggedin.Set(engine.UserPrincipalName, engine.NV(username))
		}

		if login.LogonType == 2 || login.LogonType == 11 {
			logins := topInteractiveUsers[username]
			logins++
			topInteractiveUsers[username] = logins
		}

		// loginSince := login.LastSeen.Sub(cinfo.Collected).Hours() / 24
		// switch {
		// case loginSince <= 1:
		// 	ao.EdgeTo(machine, user,  EdgeLocalSessionLastDay)
		// case loginSince <= 7:
		// 	ao.EdgeTo(machine, user,  EdgeLocalSessionLastWeek)
		// case loginSince <= 31:
		// 	ao.EdgeTo(machine, user,  EdgeLocalSessionLastMonth)
		// }

		// Parse event id 4624
		switch login.LogonType {
		case 2, 11: // Interactive or cached interactive
			ao.EdgeTo(machine, loggedin, EdgeSessionLocal)
		case 3: // Network
			ao.EdgeTo(machine, loggedin, EdgeSessionNetwork)
			switch login.AuthenticationPackageName {
			case "NTLM", "NTLM V1":
				ao.EdgeTo(machine, loggedin, EdgeSessionNetworkNTLM)
			case "NTLM V2":
				ao.EdgeTo(machine, loggedin, EdgeSessionNetworkNTLMv2)
			case "Kerberos":
				ao.EdgeTo(machine, loggedin, EdgeSessionNetworkKerberos)
			case "Negotiate":
				ao.EdgeTo(machine, loggedin, EdgeSessionNetworkNegotiate)
			default:
				ui.Debug().Msgf("Other: %v", login.AuthenticationPackageName)
			}
		case 4: // Batch (scheduled task)
			ao.EdgeTo(machine, loggedin, EdgeSessionBatch)
		case 5: // Service
			ao.EdgeTo(machine, loggedin, EdgeSessionService)
		case 10: // RDP
			ao.EdgeTo(machine, loggedin, EdgeSessionRDP)
		}
		ao.EdgeTo(machine, loggedin, EdgeSession)

		for _, ipaddress := range login.IpAddress {
			// skip localhost IPv4 and IPv6
			if ipaddress == "127.0.0.1" || strings.HasPrefix(ipaddress, "::1") {
				continue
			}

			IpMachine := ao.AddNew(
				engine.IPAddress, engine.NV(ipaddress),
				engine.Type, "Machine",
			)
			ao.EdgeTo(IpMachine, loggedin, EdgeSession)
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
			machine.Set(PrimaryUser, engine.NV(primaryuser))
		}
	}

	// AUTOLOGIN CREDENTIALS - ONLY IF DOMAIN JOINED AND IT'S TO THIS DOMAIN
	if cinfo.Machine.DefaultUsername != "" &&
		cinfo.Machine.DefaultDomain != "" &&
		strings.EqualFold(cinfo.Machine.DefaultDomain, cinfo.Machine.Domain) {
		// NETBIOS name for domain check FIXME
		user, _ := ao.FindOrAdd(
			engine.NetbiosDomain, engine.NV(cinfo.Machine.DefaultDomain),
			activedirectory.SAMAccountName, cinfo.Machine.DefaultUsername,
			engine.DownLevelLogonName, cinfo.Machine.DefaultDomain+"\\"+cinfo.Machine.DefaultUsername,
		)
		ao.EdgeTo(machine, user, EdgeHasAutoAdminLogonCredentials)
	}

	// SERVICE CONTROL MANAGER
	if len(cinfo.ServiceControlManagerSecurityDescriptor) > 0 {
		// Parse the SCM security descriptor
		if sd, err := engine.ParseSecurityDescriptor(cinfo.ServiceControlManagerSecurityDescriptor); err == nil {
			for _, entry := range sd.DACL.Entries {
				entrysid := entry.SID
				// Create service permission check
				if entry.Type == engine.ACETYPE_ACCESS_ALLOWED &&
					entry.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE == 0 &&
					entry.Mask&engine.SC_MANAGER_CREATE_SERVICE != 0 {
					o := ao.FindOrAddAdjacentSID(entrysid, machine)
					ao.EdgeTo(o, machine, EdgeCreateService)
				}
			}
		} else {
			ui.Warn().Msgf("Can't parse Service Control Manager security descriptor on %v: %v", cinfo.Machine.Name, err)
		}
	}

	// INDIVIDUAL SERVICES
	servicescontainer := engine.NewNode(activedirectory.Name, "Services")
	ao.Add(servicescontainer)
	servicescontainer.ChildOf(machine)
	// All services are a member of this group
	localservicesgroup := ao.AddNew(
		activedirectory.ObjectSid, engine.NV(windowssecurity.ServicesSID),
		engine.DownLevelLogonName, cinfo.Machine.Name+"\\Services",
		engine.DisplayName, "Services (local)",
		engine.DataSource, cinfo.Machine.Name,
		engine.Type, "Group",
	)
	localservicesgroup.ChildOf(machine)
	for _, service := range cinfo.Services {
		serviceobject := engine.NewNode(
			engine.IgnoreBlanks,
			activedirectory.Name, service.Name,
			activedirectory.DisplayName, service.Name,
			activedirectory.Description, service.Description,
			engine.DataSource, cinfo.Machine.Name,
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
		ao.EdgeTo(serviceobject, localservicesgroup, EdgeMemberOfGroup)
		ao.EdgeTo(machine, serviceobject, EdgeHosts)

		// Change service executable contents
		serviceexecutable := engine.NewNode(
			activedirectory.DisplayName, filepath.Base(service.ImageExecutable),
			AbsolutePath, service.ImageExecutable,
			engine.Type, "Executable",
		)
		ao.Add(serviceexecutable)
		ao.EdgeTo(serviceobject, serviceexecutable, EdgeExecutes)
		serviceexecutable.ChildOf(serviceobject)
		if ownersid, err := windowssecurity.ParseStringSID(service.ImageExecutableOwner); err == nil {
			owner := ao.FindOrAddAdjacentSID(ownersid, machine)
			ao.EdgeTo(owner, serviceexecutable, activedirectory.EdgeOwns)
		}
		if sd, err := engine.ParseACL(service.ImageExecutableDACL); err == nil {
			for _, entry := range sd.Entries {
				entrysid := entry.SID
				if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entrysid.Component(2) == 21 || entry.SID == windowssecurity.EveryoneSID || entry.SID == windowssecurity.AuthenticatedUsersSID) {
					o := ao.FindOrAddAdjacentSID(entrysid, machine)
					if entry.Mask&engine.FILE_WRITE_DATA != 0 {
						ao.EdgeTo(o, serviceexecutable, EdgeFileWrite)
					}
					if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
						ao.EdgeTo(o, serviceexecutable, activedirectory.EdgeTakeOwnership) // Not sure about this one
					}
					if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
						ao.EdgeTo(o, serviceexecutable, activedirectory.EdgeWriteDACL)
					}
				}
			}
			// ui.Debug().Msgf("Service %v executable %v: %v", service.Name, service.ImageExecutable, sd)
		}

		var svcaccount *engine.Node
		var serviceaccountSID windowssecurity.SID
		if service.AccountSID == "" {
			if service.Account == "" {
				serviceaccountSID = windowssecurity.SystemSID
			} else {
				switch strings.ToUpper(service.Account) {
				case "LOCALSYSTEM":
					serviceaccountSID = windowssecurity.SystemSID
				case "NT AUTHORITY\\SYSTEM":
					serviceaccountSID = windowssecurity.SystemSID
				case "NT AUTHORITY\\NETWORK SERVICE":
					serviceaccountSID = windowssecurity.NetworkServiceSID
				default:
					if strings.Contains(service.Account, "\\") {
						nameparts := strings.Split(service.Account, "\\")

						if nameparts[0] == "." {
							nameparts[0] = cinfo.Machine.Name
						}

						svcaccount, _ = ao.FindOrAdd(engine.DownLevelLogonName, engine.NV(nameparts[0]+"\\"+nameparts[1]))

						if !strings.EqualFold(nameparts[0], cinfo.Machine.Domain) {
							if svcaccount.Parent() == nil {
								svcaccount.ChildOf(serviceobject)
							}
						}
					} else if strings.Contains(service.Account, "@") {
						svcaccount, _ = ao.FindOrAdd(
							engine.UserPrincipalName, engine.NV(service.Account),
						)
					} else {
						ui.Warn().Msgf("Don't know how to parse service account name %v", service.Account)
					}
				}
			}
		} else {
			// If we have the SID use that
			serviceaccountSID, err = windowssecurity.ParseStringSID(service.AccountSID)
			if err != nil {
				ui.Warn().Msgf("Service account SID (%v) parsing problem: %v", service.AccountSID, err)
			}
		}
		if svcaccount == nil && !serviceaccountSID.IsBlank() {
			svcaccount = ao.FindOrAddAdjacentSID(serviceaccountSID, machine)
		}

		// Did we somehow manage to find an account?
		if svcaccount != nil {
			if serviceaccountSID.Component(2) == 21 || serviceaccountSID.Component(2) == 32 {
				// Foreign to computer, so it gets a direct edge
				ao.EdgeTo(machine, svcaccount, EdgeSessionService)
				ao.EdgeTo(machine, svcaccount, EdgeHasServiceAccountCredentials)
			}
			ao.EdgeTo(serviceexecutable, svcaccount, analyze.EdgeAuthenticatesAs)
		} else {
			ui.Warn().Msgf("Unhandled service credentials %+v", service)
		}

		// Specific service SID
		so := ao.FindOrAddAdjacentSID(windowssecurity.ServiceNameToServiceSID(service.Name), machine)
		// ui.Debug().Msgf("Added service account %v for service %v", so.SID().String(), service.Name)
		so.SetFlex(
			activedirectory.Name, engine.NV(service.Name),
			activedirectory.Description, engine.NV("Service virtual account for "+service.Name),
			engine.DownLevelLogonName, engine.NV("NT SERVICE\\"+service.Name),
		)
		ao.EdgeTo(serviceexecutable, so, analyze.EdgeAuthenticatesAs)

		// Change service settings directly via registry
		if service.RegistryOwner != "" {
			ro, err := windowssecurity.ParseStringSID(service.RegistryOwner)
			if err == nil {
				o := ao.FindOrAddAdjacentSID(ro, machine)
				ao.EdgeTo(o, serviceobject, EdgeRegistryOwns)
			}
		}
		if sd, err := engine.ParseACL(service.RegistryDACL); err == nil {
			for _, entry := range sd.Entries {
				entrysid := entry.SID
				if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entry.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE) == 0 {
					o := ao.FindOrAddAdjacentSID(entrysid, machine)
					if entry.Mask&engine.KEY_SET_VALUE != 0 {
						ao.EdgeTo(o, serviceobject, EdgeRegistryWrite)
					}
					if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
						ao.EdgeTo(o, serviceobject, EdgeRegistryModifyDACL)
					}
					if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
						ao.EdgeTo(o, serviceobject, activedirectory.EdgeTakeOwnership)
					}
				}
			}
		} else {
			ui.Warn().Msgf("Could not parse computer %v service %v registry security descriptor: %v", cinfo.Machine.Name, service.Name, err)
		}

		// Service security descriptor
		if len(service.SecurityDescriptor) > 0 {
			if sd, err := engine.ParseSecurityDescriptor(service.SecurityDescriptor); err == nil {
				for _, entry := range sd.DACL.Entries {
					entrysid := entry.SID
					if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entry.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE) == 0 {
						if entry.Mask&engine.SERVICE_CHANGE_CONFIG == engine.SERVICE_CHANGE_CONFIG ||
							entry.Mask&engine.SERVICE_ALL_ACCESS == engine.SERVICE_ALL_ACCESS ||
							entry.Mask&engine.WRITE_OWNER == engine.WRITE_OWNER ||
							entry.Mask&engine.WRITE_DAC == engine.WRITE_DAC {
							o := ao.FindOrAddAdjacentSID(entrysid, machine)
							ao.EdgeTo(o, serviceobject, EdgeServiceModify)
						}
					}
				}
			} else {
				ui.Warn().Msgf("Could not parse computer %v service %v security descriptor: %v", cinfo.Machine.Name, service.Name, err)
			}
		}

	}

	// SCHEDULED TASKS
	if len(cinfo.Tasks) > 0 {
		taskcontainer := engine.NewNode(activedirectory.Name, "Scheduled Tasks")
		ao.Add(taskcontainer)
		taskcontainer.ChildOf(machine)
		for _, task := range cinfo.Tasks {
			taskobject := ao.AddNew(
				engine.IgnoreBlanks,
				activedirectory.Name, task.Name,
				activedirectory.Description, task.Definition.RegistrationInfo.Description,
				// ScheduledTaskPath, task.Path,
				// engine.Enabled, task.Enabled,
				engine.Type, "ScheduledTask",
			)
			taskobject.ChildOf(taskcontainer)
			ao.EdgeTo(machine, taskobject, EdgeHosts)
			switch task.Definition.Principal.LogonType {
			case TASK_LOGON_GROUP:
				// When someone that is a member of the group is logged in
				// task.Definition.Principal.GroupID == "Everyone"
			case TASK_LOGON_SERVICE_ACCOUNT:
				if task.Definition.Principal.UserID == "LOCAL SERVICE" {
					// "LOCAL SERVICE"
				}
				if task.Definition.Principal.UserID == "SYSTEM" && task.Definition.Principal.RunLevel == 1 {
					// Elevated as system
					system := ao.FindOrAddAdjacentSID(windowssecurity.SystemSID, machine)
					ao.EdgeTo(taskobject, system, analyze.EdgeAuthenticatesAs)
				}
				if strings.HasPrefix(task.Definition.Principal.UserID, "\\") {
					ui.Debug().Msgf("Odd service account in scheduled task %v: %v", task.Name, task.Definition.Principal.UserID)
				}
			}

			// DACL that can change the task
			if task.Definition.RegistrationInfo.SecurityDescriptor != "" {
				if sd, err := engine.ParseSDDL(task.Definition.RegistrationInfo.SecurityDescriptor); err == nil {
					for _, entry := range sd.Entries {
						entrysid := entry.SID
						if entrysid == windowssecurity.AdministratorsSID || entrysid == windowssecurity.SystemSID || entrysid.Component(2) == 80 /* Service user */ {
							// if we have local admin it's already game over so don't map this
							continue
						}
						if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entry.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE) == 0 {
							var sidNode *engine.Node
							if entry.Mask&engine.WRITE_DAC == engine.WRITE_DAC {
								if sidNode == nil {
									sidNode = ao.FindOrAddAdjacentSID(entrysid, machine)
								}
								ao.EdgeTo(sidNode, taskobject, activedirectory.EdgeWriteDACL)
							}
							if entry.Mask&engine.WRITE_OWNER != engine.WRITE_OWNER {
								if sidNode == nil {
									sidNode = ao.FindOrAddAdjacentSID(entrysid, machine)
								}
								ao.EdgeTo(sidNode, taskobject, activedirectory.EdgeTakeOwnership)
							}
							if entry.Mask&engine.TASK_WRITE == engine.TASK_WRITE {
								if sidNode == nil {
									sidNode = ao.FindOrAddAdjacentSID(entrysid, machine)
								}
								ao.EdgeTo(sidNode, taskobject, activedirectory.EdgeWriteAll)
							}
							if entry.Mask&engine.TASK_FULL_CONTROL == engine.TASK_FULL_CONTROL {
								if sidNode == nil {
									sidNode = ao.FindOrAddAdjacentSID(entrysid, machine)
								}
								ao.EdgeTo(sidNode, taskobject, activedirectory.EdgeGenericAll)
							}
						}
					}
				}
			}
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
			ao.EdgeTo(machine, shareobject, EdgeShares)
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
						o := ao.FindOrAddAdjacentSID(entrysid, machine)
						if entry.Mask&engine.FILE_READ_DATA != 0 {
							ao.EdgeTo(o, shareobject, EdgeFileRead)
						}
						if entry.Mask&engine.FILE_WRITE_DATA != 0 {
							ao.EdgeTo(o, shareobject, EdgeFileWrite)
						}
						if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
							ao.EdgeTo(o, shareobject, activedirectory.EdgeTakeOwnership) // Not sure about this one
						}
						if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
							ao.EdgeTo(o, shareobject, activedirectory.EdgeWriteDACL)
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
			ao.EdgeTo(shareobject, pathobject, EdgePublishes)
			// File rights
			if sd, err := engine.CacheOrParseSecurityDescriptor(string(share.PathDACL)); err == nil {
				if !sd.Owner.IsNull() {
					owner := ao.FindOrAddAdjacentSID(sd.Owner, machine)
					ao.EdgeTo(owner, pathobject, activedirectory.EdgeOwns)
				}
				for _, entry := range sd.DACL.Entries {
					entrysid := entry.SID
					if entry.Type == engine.ACETYPE_ACCESS_ALLOWED {
						aclsid := ao.FindOrAddAdjacentSID(entrysid, machine)
						if entry.Mask&engine.FILE_READ_DATA != 0 {
							ao.EdgeTo(aclsid, pathobject, EdgeFileRead)
						}
						if entry.Mask&engine.FILE_WRITE_DATA != 0 {
							ao.EdgeTo(aclsid, pathobject, EdgeFileWrite)
						}
						if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
							ao.EdgeTo(aclsid, pathobject, activedirectory.EdgeTakeOwnership) // Not sure about this one
						}
						if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
							ao.EdgeTo(aclsid, pathobject, activedirectory.EdgeWriteDACL)
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
			activedirectory.ObjectSid, engine.NV(windowssecurity.EveryoneSID),
			engine.DataSource, engine.NV(cinfo.Machine.Domain),
		)
		// Everyone who is a member of the Domain is also a member of "our" Everyone
		ao.EdgeTo(domaineveryoneobject, everyone, activedirectory.EdgeMemberOfGroup)
		domainauthenticatedusers := ao.AddNew(
			activedirectory.ObjectSid, engine.NV(windowssecurity.AuthenticatedUsersSID),
			engine.DataSource, engine.NV(cinfo.Machine.Domain),
		)
		ao.EdgeTo(domainauthenticatedusers, authenticatedUsers, activedirectory.EdgeMemberOfGroup)
	}
	return machine, nil
}
