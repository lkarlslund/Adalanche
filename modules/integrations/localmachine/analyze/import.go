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
func ImportCollectorInfo(tx *engine.Tx, cinfo localmachine.Info) (engine.TxNode, error) {
	// Every collection is a machine of its own. Several collections can
	// claim the same computer account (a machine collected twice, or
	// clones); which one is current is decided when all are loaded.
	machine := tx.AddNew()
	// See if the machine has a unique SID
	localsid, err := windowssecurity.ParseStringSID(cinfo.Machine.LocalSID)
	if err != nil {
		return engine.TxNode{}, fmt.Errorf("collected localmachine information for %v doesn't contain valid local machine SID (%v): %v", cinfo.Machine.Name, cinfo.Machine.LocalSID, err)
	}
	var domainsid windowssecurity.SID
	if cinfo.Machine.IsDomainJoined {
		domainsid, err = windowssecurity.ParseStringSID(cinfo.Machine.ComputerDomainSID)
		if cinfo.Machine.ComputerDomainSID != "" && err == nil {
			machine.Set(analyze.DomainJoinedSID, engine.NV(domainsid))
			// Link to the AD account
			computer, _ := tx.FindOrAdd(
				activedirectory.ObjectSid, engine.NV(domainsid),
			)
			downlevelmachinename := cinfo.Machine.Domain + "\\" + cinfo.Machine.Name + "$"
			computer.SetFlex(
				activedirectory.SAMAccountName, engine.NV(strings.ToUpper(cinfo.Machine.Name)+"$"),
				engine.DownLevelLogonName, engine.NV(downlevelmachinename),
			)
			tx.EdgeBecause(machine, computer, analyze.EdgeAuthenticatesAs, Collected("domain membership"))
			tx.EdgeBecause(machine, computer, analyze.EdgeMachineAccount, Collected("domain membership"))
			machine.ChildOf(computer)
		}
	} else {
		ui.Debug().Msg("NOT JOINED??")
	}
	if cinfo.UnprivilegedCollection {
		ui.Info().Msgf("Loading partial information from unprivileged collector on machine %v", cinfo.Machine.Name)
	}
	machine.SetFlex(
		engine.IgnoreBlanks,
		localmachine.CollectedAt, cinfo.Collected,
		localmachine.SMBIOSUUID, cinfo.Machine.SMBIOSUUID,
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
	isdomaincontroller := isDomainController(cinfo)
	scope := NewMachineScope(tx, machine, cinfo)
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
	everyone := scope.Principal(windowssecurity.EveryoneSID)
	everyone.SetFlex(engine.Type, "Group") // This could go wrong
	everyone.ChildOf(machine)
	authenticatedUsers := scope.Principal(windowssecurity.AuthenticatedUsersSID)
	authenticatedUsers.SetFlex(engine.Type, "Group") // This could go wrong
	tx.EdgeBecause(authenticatedUsers, everyone, activedirectory.EdgeMemberOfGroup, Collected("built-in groups"))
	authenticatedUsers.ChildOf(machine)
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
	// Add local accounts as synthetic objects
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
				localUser := tx.AddNew(
					engine.IgnoreBlanks,
					activedirectory.ObjectSid, engine.NV(usid),
					activedirectory.Type, "Person",
					activedirectory.DisplayName, user.FullName,
					activedirectory.Name, user.Name,
					activedirectory.UserAccountControl, uac,
					activedirectory.PwdLastSet, user.PasswordLastSet,
					activedirectory.LastLogon, user.LastLogon,
					engine.DownLevelLogonName, downLevelLogonName(cinfo.Machine.Name, user.Name),
					activedirectory.BadPwdCount, user.BadPasswordCount,
					activedirectory.LogonCount, user.NumberOfLogins,
					engine.DataSource, uniquesource,
				)
				localUser.ChildOf(machine)
				tx.EdgeBecause(localUser, authenticatedUsers, activedirectory.EdgeMemberOfGroup, Collected("built-in groups"))

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
		for _, group := range cinfo.Groups {
			groupsid, err := windowssecurity.ParseStringSID(group.SID)
			if err != nil {
				ui.Warn().Msgf("Can't convert local group SID %v: %v", group.SID, err)
				continue
			}
			// Potential translation
			localGroup := tx.AddNew(
				engine.IgnoreBlanks,
				activedirectory.ObjectSid, engine.NV(groupsid),
				activedirectory.Name, group.Name,
				activedirectory.Description, group.Comment,
				engine.Type, "Group",
				engine.DataSource, uniquesource,
			)
			localGroup.ChildOf(machine)
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
				memberobject := scope.Principal(membersid)
				// Collector sometimes returns junk, but if we have downlevel logon name we store it
				if member.Name != "" && !strings.HasSuffix(member.Name, "\\") && !strings.HasPrefix(member.Name, "S-1-") {
					memberobject.SetFlex(
						engine.DownLevelLogonName, member.Name,
					)
				}
				inGroup := Collected("local group "+group.Name)
				tx.EdgeBecause(memberobject, localGroup, activedirectory.EdgeMemberOfGroup, inGroup)
				switch {
				case group.Name == "SMS Admins":
					tx.EdgeBecause(localGroup, machine, EdgeLocalSMSAdmins, inGroup)
				case groupsid == windowssecurity.AdministratorsSID:
					tx.EdgeBecause(localGroup, machine, EdgeLocalAdminRights, inGroup)
				case groupsid == windowssecurity.DCOMUsersSID:
					tx.EdgeBecause(localGroup, machine, EdgeLocalDCOMRights, inGroup)
				case groupsid == windowssecurity.RemoteDesktopUsersSID:
					if !locallyDeniedLogon(cinfo, groupsid.String(), "SeDenyRemoteInteractiveLogonRight") {
						tx.EdgeBecause(localGroup, machine, EdgeLocalRDPRights, inGroup)
					}
				}
				if memberobject.Node().HasAttr(engine.DataSource) {
					// Maybe a deleted user or group
					if memberobject.Node().Parent() == nil {
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
			if pi.Name == "SeNetworkLogonRight" && locallyDeniedLogon(cinfo, sidstring, "SeDenyNetworkLogonRight") {
				continue
			}
			if pi.Name == "SeRemoteInteractiveLogonRight" && locallyDeniedLogon(cinfo, sidstring, "SeDenyRemoteInteractiveLogonRight") {
				continue
			}
			sid, err := windowssecurity.ParseStringSID(sidstring)
			if err != nil {
				ui.Error().Msgf("Invalid SID %v: %v", sidstring, err)
				continue
			}
			// Potential translation
			assignee := scope.Principal(sid)
			tx.EdgeBecause(assignee, machine, edge, Collected("user right "+pi.Name))
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
		loggedin := scope.Principal(usersid)
		if usersid.StripRID() == localsid || usersid.Component(2) != 21 {
			loggedin.SetFlex(
				engine.DataSource, uniquesource,
			)
		}
		var username string
		if !strings.Contains(login.Domain, ".") {
			username = login.Domain + "\\" + login.User
			if name := downLevelLogonName(login.Domain, login.User); name != "" {
				loggedin.Set(engine.DownLevelLogonName, engine.NV(name))
			}
		} else {
			// user.Set(engine.SAMAccountName, engine.NewAttributeValueString(login.User))
			username = login.User + "@" + login.Domain
			loggedin.Set(engine.UserPrincipalName, engine.NV(username))
		}

		if login.LogonType == 2 || login.LogonType == 11 {
			logins := topInteractiveUsers[username]
			logins += int(login.Count)
			topInteractiveUsers[username] = logins
		}

		// loginSince := login.LastSeen.Sub(cinfo.Collected).Hours() / 24
		// switch {
		// case loginSince <= 1:
		// 	tx.EdgeTo(machine, user,  EdgeLocalSessionLastDay)
		// case loginSince <= 7:
		// 	tx.EdgeTo(machine, user,  EdgeLocalSessionLastWeek)
		// case loginSince <= 31:
		// 	tx.EdgeTo(machine, user,  EdgeLocalSessionLastMonth)
		// }

		// Parse event id 4624
		switch login.LogonType {
		case 2, 11: // Interactive or cached interactive
			tx.EdgeBecause(machine, loggedin, EdgeSessionLocal, Collected("logon sessions"))
		case 3: // Network
			tx.EdgeBecause(machine, loggedin, EdgeSessionNetwork, Collected("logon sessions"))
			switch login.AuthenticationPackageName {
			case "NTLM", "NTLM V1":
				tx.EdgeBecause(machine, loggedin, EdgeSessionNetworkNTLM, Collected("logon sessions"))
			case "NTLM V2":
				tx.EdgeBecause(machine, loggedin, EdgeSessionNetworkNTLMv2, Collected("logon sessions"))
			case "Kerberos":
				tx.EdgeBecause(machine, loggedin, EdgeSessionNetworkKerberos, Collected("logon sessions"))
			case "Negotiate":
				tx.EdgeBecause(machine, loggedin, EdgeSessionNetworkNegotiate, Collected("logon sessions"))
			default:
				ui.Debug().Msgf("Other: %v", login.AuthenticationPackageName)
			}
		case 4: // Batch (scheduled task)
			tx.EdgeBecause(machine, loggedin, EdgeSessionBatch, Collected("logon sessions"))
		case 5: // Service
			tx.EdgeBecause(machine, loggedin, EdgeSessionService, Collected("logon sessions"))
		case 10: // RDP
			tx.EdgeBecause(machine, loggedin, EdgeSessionRDP, Collected("logon sessions"))
		}
		tx.EdgeBecause(machine, loggedin, EdgeSession, Collected("logon sessions"))

		for _, ipaddress := range login.IpAddress {
			// skip localhost IPv4 and IPv6
			if ipaddress == "127.0.0.1" || strings.HasPrefix(ipaddress, "::1") {
				continue
			}

			IpMachine := tx.AddNew(
				engine.IPAddress, engine.NV(ipaddress),
				engine.Type, "Machine",
			)
			tx.EdgeBecause(IpMachine, loggedin, EdgeSession, Collected("logon sessions"))
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
		user, _ := tx.FindOrAdd(
			engine.NetbiosDomain, engine.NV(cinfo.Machine.DefaultDomain),
			activedirectory.SAMAccountName, cinfo.Machine.DefaultUsername,
			engine.DownLevelLogonName, cinfo.Machine.DefaultDomain+"\\"+cinfo.Machine.DefaultUsername,
		)
		tx.EdgeBecause(machine, user, EdgeHasAutoAdminLogonCredentials, Collected("AutoAdminLogon"))
	}

	// SERVICE CONTROL MANAGER
	if len(cinfo.ServiceControlManagerSecurityDescriptor) > 0 {
		// Parse the SCM security descriptor
		if sd, err := engine.ParseSecurityDescriptor(cinfo.ServiceControlManagerSecurityDescriptor); err == nil {
			for index, entry := range sd.DACL.Entries {
				entrysid := entry.SID
				// Create service permission check
				if entry.Type == engine.ACETYPE_ACCESS_ALLOWED &&
					entry.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE == 0 &&
					entry.Mask&engine.SC_MANAGER_CREATE_SERVICE != 0 {
					o := scope.Principal(entrysid)
					tx.EdgeBecause(o, machine, EdgeCreateService, Collected(fmt.Sprintf("service control manager ACE %d", index)))
				}
			}
		} else {
			ui.Warn().Msgf("Can't parse Service Control Manager security descriptor on %v: %v", cinfo.Machine.Name, err)
		}
	}

	// INDIVIDUAL SERVICES
	// Keep the security principal, but create it only for retained services.
	var localservicesgroup engine.TxNode
	var skippedServiceSIDs []windowssecurity.SID
	admin := machineAdmins(cinfo.Services)
	for _, service := range cinfo.Services {
		keepService := !serviceAdminOnly(service, admin)
		var serviceobject, serviceexecutable engine.TxNode
		if keepService {
			if !localservicesgroup.Valid() {
				localservicesgroup = scope.Principal(windowssecurity.ServicesSID)
				localservicesgroup.SetFlex(
					activedirectory.ObjectSid, engine.NV(windowssecurity.ServicesSID),
					engine.DownLevelLogonName, cinfo.Machine.Name+"\\Services",
					engine.DisplayName, "Services (local)",
					engine.DataSource, cinfo.Machine.Name,
					engine.Type, "Group",
				)
				localservicesgroup.ChildOf(machine)
			}
			serviceobject = tx.AddNew(
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
			if start := serviceStartName(service.Start); start != "unknown" {
				serviceobject.Tag("service_" + start)
			}
			serviceobject.ChildOf(machine)
			tx.EdgeBecause(serviceobject, localservicesgroup, EdgeMemberOfGroup, Collected("service "+service.Name))
			tx.EdgeBecause(machine, serviceobject, EdgeHosts, Collected("service "+service.Name))

			// Change service executable contents
			serviceexecutable = tx.AddNew(
				activedirectory.DisplayName, filepath.Base(service.ImageExecutable),
				AbsolutePath, service.ImageExecutable,
				engine.Type, "Executable",
			)
			tx.EdgeBecause(serviceobject, serviceexecutable, EdgeExecutes, Collected("service "+service.Name))
			serviceexecutable.ChildOf(serviceobject)
			if ownersid, err := windowssecurity.ParseStringSID(service.ImageExecutableOwner); err == nil {
				owner := scope.Principal(ownersid)
				tx.EdgeBecause(owner, serviceexecutable, activedirectory.EdgeOwns, Collected("service "+service.Name+" executable owner"))
			}
			if sd, err := engine.ParseACL(service.ImageExecutableDACL); err == nil {
				for index, entry := range sd.Entries {
					entrysid := entry.SID
					if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entrysid.Component(2) == 21 || entry.SID == windowssecurity.EveryoneSID || entry.SID == windowssecurity.AuthenticatedUsersSID) {
						o := scope.Principal(entrysid)
						if entry.Mask&engine.FILE_WRITE_DATA != 0 {
							tx.EdgeBecause(o, serviceexecutable, EdgeFileWrite, Collected(fmt.Sprintf("service %v executable ACE %d", service.Name, index)))
						}
						if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
							tx.EdgeBecause(o, serviceexecutable, activedirectory.EdgeTakeOwnership, Collected(fmt.Sprintf("service %v executable ACE %d", service.Name, index))) // Not sure about this one
						}
						if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
							tx.EdgeBecause(o, serviceexecutable, activedirectory.EdgeWriteDACL, Collected(fmt.Sprintf("service %v executable ACE %d", service.Name, index)))
						}
					}
				}
				// ui.Debug().Msgf("Service %v executable %v: %v", service.Name, service.ImageExecutable, sd)
			}

		}
		var svcaccount engine.TxNode
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
					if domain, user, found := strings.Cut(service.Account, "\\"); found {
						if domain == "." {
							domain = cinfo.Machine.Name
						}
						user, _, _ = strings.Cut(user, "\\")
						if name := downLevelLogonName(domain, user); name != "" {
							svcaccount, _ = tx.FindOrAdd(engine.DownLevelLogonName, engine.NV(name))
							if !strings.EqualFold(domain, cinfo.Machine.Domain) && svcaccount.Node().Parent() == nil {
								svcaccount.ChildOf(machine)
							}
						}
					} else if strings.Contains(service.Account, "@") {
						svcaccount, _ = tx.FindOrAdd(
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
		if !svcaccount.Valid() && !serviceaccountSID.IsBlank() {
			svcaccount = scope.Principal(serviceaccountSID)
		}

		// Did we somehow manage to find an account?
		if svcaccount.Valid() {
			if serviceaccountSID.Component(2) == 21 || serviceaccountSID.Component(2) == 32 {
				// Foreign to computer, so it gets a direct edge
				tx.EdgeBecause(machine, svcaccount, EdgeSessionService, Collected("service "+service.Name+" account"))
				tx.EdgeBecause(machine, svcaccount, EdgeHasServiceAccountCredentials, Collected("service "+service.Name+" account"))
			}
			if keepService {
				tx.EdgeBecause(serviceexecutable, svcaccount, analyze.EdgeAuthenticatesAs, Collected("service "+service.Name+" account"))
			} else {
				// Preserve the execution identity formerly reached through Hosts
				// and Executes, including accounts identified only by name.
				tx.EdgeBecause(machine, svcaccount, analyze.EdgeAuthenticatesAs, Collected("service "+service.Name+" account"))
			}
		} else {
			ui.Warn().Msgf("Unhandled service credentials %+v", service)
		}

		if !keepService {
			skippedServiceSIDs = append(skippedServiceSIDs, windowssecurity.ServiceNameToServiceSID(service.Name))
			continue
		}
		// Specific service SID
		so := scope.Principal(windowssecurity.ServiceNameToServiceSID(service.Name))
		// ui.Debug().Msgf("Added service account %v for service %v", so.SID().String(), service.Name)
		so.SetFlex(
			activedirectory.Name, engine.NV(service.Name),
			activedirectory.Description, engine.NV("Service virtual account for "+service.Name),
			engine.DownLevelLogonName, engine.NV("NT SERVICE\\"+service.Name),
		)
		tx.EdgeBecause(serviceexecutable, so, analyze.EdgeAuthenticatesAs, Collected("service "+service.Name+" virtual account"))

		// Change service settings directly via registry
		if service.RegistryOwner != "" {
			ro, err := windowssecurity.ParseStringSID(service.RegistryOwner)
			if err == nil {
				o := scope.Principal(ro)
				tx.EdgeBecause(o, serviceobject, EdgeRegistryOwns, Collected("service "+service.Name+" registry owner"))
			}
		}
		if sd, err := engine.ParseACL(service.RegistryDACL); err == nil {
			for index, entry := range sd.Entries {
				entrysid := entry.SID
				if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entry.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE) == 0 {
					o := scope.Principal(entrysid)
					if entry.Mask&engine.KEY_SET_VALUE != 0 {
						tx.EdgeBecause(o, serviceobject, EdgeRegistryWrite, Collected(fmt.Sprintf("service %v registry ACE %d", service.Name, index)))
					}
					if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
						tx.EdgeBecause(o, serviceobject, EdgeRegistryModifyDACL, Collected(fmt.Sprintf("service %v registry ACE %d", service.Name, index)))
					}
					if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
						tx.EdgeBecause(o, serviceobject, activedirectory.EdgeTakeOwnership, Collected(fmt.Sprintf("service %v registry ACE %d", service.Name, index)))
					}
				}
			}
		} else {
			ui.Warn().Msgf("Could not parse computer %v service %v registry security descriptor: %v", cinfo.Machine.Name, service.Name, err)
		}

		// Service security descriptor
		if len(service.SecurityDescriptor) > 0 {
			if sd, err := engine.ParseSecurityDescriptor(service.SecurityDescriptor); err == nil {
				for index, entry := range sd.DACL.Entries {
					entrysid := entry.SID
					if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entry.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE) == 0 {
						if entry.Mask&engine.SERVICE_CHANGE_CONFIG == engine.SERVICE_CHANGE_CONFIG ||
							entry.Mask&engine.SERVICE_ALL_ACCESS == engine.SERVICE_ALL_ACCESS ||
							entry.Mask&engine.WRITE_OWNER == engine.WRITE_OWNER ||
							entry.Mask&engine.WRITE_DAC == engine.WRITE_DAC {
							o := scope.Principal(entrysid)
							tx.EdgeBecause(o, serviceobject, EdgeServiceModify, Collected(fmt.Sprintf("service %v ACE %d", service.Name, index)))
						}
					}
				}
			} else {
				ui.Warn().Msgf("Could not parse computer %v service %v security descriptor: %v", cinfo.Machine.Name, service.Name, err)
			}
		}

	}

	// SCHEDULED TASKS
	for _, task := range cinfo.Tasks {
		importTask(tx, machine, scope, task, admin)
	}

	// SERVICE AND TASK INVENTORY AS ATTRIBUTES: services and tasks that
	// only the machine's admins control are not nodes of their own.
	if len(cinfo.Services) > 0 {
		names := make([]string, len(cinfo.Services))
		for i, service := range cinfo.Services {
			names[i] = service.Name + " (" + serviceStartName(service.Start) + ")"
		}
		machine.SetFlex(localmachine.InstalledServices, names)
	}
	if len(cinfo.Tasks) > 0 {
		names := make([]string, 0, len(cinfo.Tasks))
		for _, task := range cinfo.Tasks {
			if task.Name != "" {
				names = append(names, task.Name)
			}
		}
		machine.SetFlex(localmachine.InstalledTasks, names)
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
		for _, share := range cinfo.Shares {
			shareobject := tx.AddNew(
				engine.IgnoreBlanks,
				activedirectory.DisplayName, "\\\\"+cinfo.Machine.Name+"\\"+share.Name,
				AbsolutePath, share.Path,
				engine.Description, share.Remark,
				ShareType, share.Type,
				engine.Type, "Share",
			)
			tx.EdgeBecause(machine, shareobject, EdgeShares, Collected("share "+share.Name))
			shareobject.ChildOf(machine)
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
				for index, entry := range sd.DACL.Entries {
					if entry.Type == engine.ACETYPE_ACCESS_ALLOWED {
						entrysid := entry.SID
						o := scope.Principal(entrysid)
						if entry.Mask&engine.FILE_READ_DATA != 0 {
							tx.EdgeBecause(o, shareobject, EdgeFileRead, Collected(fmt.Sprintf("share %v ACE %d", share.Name, index)))
						}
						if entry.Mask&engine.FILE_WRITE_DATA != 0 {
							tx.EdgeBecause(o, shareobject, EdgeFileWrite, Collected(fmt.Sprintf("share %v ACE %d", share.Name, index)))
						}
						if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
							tx.EdgeBecause(o, shareobject, activedirectory.EdgeTakeOwnership, Collected(fmt.Sprintf("share %v ACE %d", share.Name, index))) // Not sure about this one
						}
						if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
							tx.EdgeBecause(o, shareobject, activedirectory.EdgeWriteDACL, Collected(fmt.Sprintf("share %v ACE %d", share.Name, index)))
						}
					} else if entry.Type == engine.ACETYPE_ACCESS_ALLOWED_OBJECT {
						ui.Debug().Msg("Fixme")
					}
				}
			} else {
				ui.Warn().Msgf("Could not parse machine %v file share %v security descriptor", cinfo.Machine.Name, share.Name)
			}
			pathobject := tx.AddNew(
				engine.IgnoreBlanks,
				activedirectory.DisplayName, share.Path,
				AbsolutePath, share.Path,
				engine.Type, "Directory",
			)
			pathobject.ChildOf(machine)
			tx.EdgeBecause(shareobject, pathobject, EdgePublishes, Collected("share "+share.Name))
			// File rights
			if sd, err := engine.ParseACL(share.PathDACL); err == nil {
				if sid, err := windowssecurity.ParseStringSID(share.PathOwner); err == nil {
					owner := scope.Principal(sid)
					tx.EdgeBecause(owner, pathobject, activedirectory.EdgeOwns, Collected("share "+share.Name+" folder owner"))
				}
				for index, entry := range sd.Entries {
					entrysid := entry.SID
					if entry.Type == engine.ACETYPE_ACCESS_ALLOWED {
						aclsid := scope.Principal(entrysid)
						if entry.Mask&engine.FILE_READ_DATA != 0 {
							tx.EdgeBecause(aclsid, pathobject, EdgeFileRead, Collected(fmt.Sprintf("share %v folder ACE %d", share.Name, index)))
						}
						if entry.Mask&engine.FILE_WRITE_DATA != 0 {
							tx.EdgeBecause(aclsid, pathobject, EdgeFileWrite, Collected(fmt.Sprintf("share %v folder ACE %d", share.Name, index)))
						}
						if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
							tx.EdgeBecause(aclsid, pathobject, activedirectory.EdgeTakeOwnership, Collected(fmt.Sprintf("share %v folder ACE %d", share.Name, index))) // Not sure about this one
						}
						if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
							tx.EdgeBecause(aclsid, pathobject, activedirectory.EdgeWriteDACL, Collected(fmt.Sprintf("share %v folder ACE %d", share.Name, index)))
						}
					} else if entry.Type == engine.ACETYPE_ACCESS_ALLOWED_OBJECT {
						ui.Debug().Msgf("Fixme")
					}
				}
			}
		}
	}
	// The domain's Everyone and Authenticated Users are linked to the
	// machine's own after loading (linkDomainGroupsToMachines).
	// An omitted service's identity may still be an ACL trustee elsewhere.
	// Retain that path without creating otherwise unused service identities.
	for _, sid := range skippedServiceSIDs {
		if identity, found := tx.FindAdjacentSID(sid, machine.Node()); found {
			tx.EdgeBecause(machine, identity, analyze.EdgeAuthenticatesAs, Collected("service accounts of admin-only services"))
		}
	}
	if err := importCollectionSettings(machine, cinfo); err != nil {
		return engine.TxNode{}, err
	}
	if err := importLocalEvidence(machine, cinfo); err != nil {
		return engine.TxNode{}, err
	}
	importPolicyProvenance(tx, machine, cinfo)
	return machine, nil
}

// downLevelLogonName joins a domain and an account name into DOMAIN\account.
// It returns "" when either part is missing, as collectors sometimes report,
// since a partial name would match unrelated accounts.
func downLevelLogonName(domain, account string) string {
	domain, account = strings.TrimSpace(domain), strings.TrimSpace(account)
	if domain == "" || account == "" || strings.HasSuffix(account, "\\") {
		return ""
	}
	return domain + "\\" + account
}
