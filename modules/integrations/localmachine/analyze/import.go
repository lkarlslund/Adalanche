package analyze

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/ui"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// Returns the computer object
func ImportCollectorInfo(ao *engine.Objects, cinfo localmachine.Info) (*engine.Object, error) {
	var machine *engine.Object
	var existing bool

	// See if the machine has a unique SID
	localsid, err := windowssecurity.ParseStringSID(cinfo.Machine.LocalSID)
	if err != nil {
		return nil, fmt.Errorf("collected localmachine information for %v doesn't contain valid local machine SID (%v): %v", cinfo.Machine.Name, cinfo.Machine.LocalSID, err)
	}

	if cinfo.Machine.IsDomainJoined {
		domainsid, err := windowssecurity.ParseStringSID(cinfo.Machine.ComputerDomainSID)
		if cinfo.Machine.ComputerDomainSID != "" && err == nil {
			machine, existing = ao.FindOrAdd(
				analyze.DomainJoinedSID, engine.AttributeValueSID(domainsid),
			)
			// It's a duplicate domain member SID :-(
			if existing {
				return nil, fmt.Errorf("duplicate machine info for domain account SID %v found, not loading it. machine names %v and %v", cinfo.Machine.ComputerDomainSID, cinfo.Machine.Name, machine.Label())
			}

			// Link to the AD account
			computer, _ := ao.FindOrAdd(
				activedirectory.ObjectSid, engine.AttributeValueSID(domainsid),
			)

			downlevelmachinename := cinfo.Machine.Domain + "\\" + cinfo.Machine.Name + "$"
			computer.SetFlex(
				activedirectory.SAMAccountName, engine.AttributeValueString(strings.ToUpper(cinfo.Machine.Name)+"$"),
				engine.DownLevelLogonName, engine.AttributeValueString(downlevelmachinename),
			)

			machine.EdgeTo(computer, analyze.EdgeAuthenticatesAs)
			machine.EdgeTo(computer, analyze.EdgeMachineAccount)
			machine.ChildOf(computer)
		}
	} else {
		ui.Debug().Msg("NOT JOINED??")
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
		engine.ObjectCategorySimple, engine.AttributeValueString("Machine"),
		engine.NewAttribute("connectivity"), cinfo.Network.InternetConnectivity,
	)

	if cinfo.Machine.WUServer != "" {
		if u, err := url.Parse(cinfo.Machine.WUServer); err == nil {
			host, _, _ := strings.Cut(u.Host, ":")
			machine.SetFlex(
				WUServer, engine.AttributeValueString(host),
			)
		}
	}

	if cinfo.Machine.SCCMLastValidMP != "" {
		if u, err := url.Parse(cinfo.Machine.SCCMLastValidMP); err == nil {
			host, _, _ := strings.Cut(u.Host, ":")
			machine.SetFlex(
				SCCMServer, engine.AttributeValueString(host),
			)
		}
	}

	var isdomaincontroller bool
	if cinfo.Machine.ProductType != "" && !strings.EqualFold(cinfo.Machine.ProductType, "SERVERNT") && !strings.EqualFold(cinfo.Machine.ProductType, "WINNT") {
		ui.Debug().Msgf("ProductType %v - %v", cinfo.Machine.ProductType, cinfo.Machine.ProductName)
	}

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
	uniquesource := cinfo.Machine.Name

	// Set source to domain NetBios name if we're a DC
	if isdomaincontroller {
		uniquesource = cinfo.Machine.Domain
	}

	// Don't set UniqueSource on the computer object, it needs to merge with the AD object!
	machine.SetFlex(engine.DataSource, uniquesource)

	everyoneobject, _ := ao.FindTwoOrAdd(
		engine.ObjectSid, engine.AttributeValueSID(windowssecurity.EveryoneSID),
		engine.DataSource, engine.AttributeValueString(uniquesource),
		engine.ObjectCategorySimple, "Group",
	)

	authenticatedusers, _ := ao.FindTwoOrAdd(
		engine.ObjectSid, engine.AttributeValueSID(windowssecurity.AuthenticatedUsersSID),
		engine.DataSource, engine.AttributeValueString(uniquesource),
		engine.ObjectCategorySimple, "Group",
	)

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

	if !isdomaincontroller {
		for _, user := range cinfo.Users {
			uac := 512
			if !user.IsEnabled {
				uac += 2
			}
			if user.IsLocked {
				uac += 16
			}
			if user.NoChangePassword {
				uac += 0x10000
			}
			usid, err := windowssecurity.ParseStringSID(user.SID)
			if err == nil {
				user := ao.AddNew(
					engine.IgnoreBlanks,
					activedirectory.ObjectSid, engine.AttributeValueSID(usid),
					activedirectory.ObjectCategorySimple, "Person",
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
				user.ChildOf(userscontainer)
				user.EdgeTo(everyoneobject, activedirectory.EdgeMemberOfGroup)
				user.EdgeTo(authenticatedusers, activedirectory.EdgeMemberOfGroup)
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
			// groupsid = MapSID(originalsid, localsid, groupsid)

			groupobject := ao.AddNew(
				activedirectory.ObjectSid, engine.AttributeValueSID(groupsid),
				activedirectory.Name, group.Name,
				activedirectory.Description, group.Comment,
				engine.ObjectCategorySimple, "Group",
				engine.DataSource, uniquesource,
			)

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
					// Some members show up with the SID in the name field FML
					membersid, err = windowssecurity.ParseStringSID(member.Name)
					if err != nil {
						ui.Info().Msgf("Fallback SID translation on %v failed: %v", member.Name, err)
						continue
					}
				}

				if membersid.Component(2) != 21 {
					continue // Not a local or domain SID, skip it
				}

				if membersid.Components() != 7 {
					ui.Warn().Msgf("Malformed SID from collector: %v, skipping member entry entirely", membersid.String())
					continue
				}

				// Collector sometimes returns junk, remove it
				if strings.HasSuffix(member.Name, "\\") || strings.HasPrefix(member.Name, "S-1-") {
					// If name resolution fails, you end up with DOMAIN\ and nothing else
					member.Name = ""
				}

				// Potential translation
				// membersid = MapSID(originalsid, localsid, membersid)

				memberobject := ao.AddNew(
					activedirectory.ObjectSid, engine.AttributeValueSID(membersid),
					engine.IgnoreBlanks,
					engine.DownLevelLogonName, member.Name,
				)

				if membersid.StripRID() == localsid || (membersid.Component(2) != 21 && membersid != windowssecurity.EveryoneSID && membersid != windowssecurity.AuthenticatedUsersSID) {
					memberobject.SetFlex(
						engine.DataSource, uniquesource,
					)
				}

				memberobject.EdgeTo(groupobject, activedirectory.EdgeMemberOfGroup)

				switch {
				case group.Name == "SMS Admins":
					memberobject.EdgeTo(machine, EdgeLocalSMSAdmins)
				case groupsid == windowssecurity.AdministratorsSID:
					memberobject.EdgeTo(machine, EdgeLocalAdminRights)
				case groupsid == windowssecurity.DCOMUsersSID:
					memberobject.EdgeTo(machine, EdgeLocalDCOMRights)
				case groupsid == windowssecurity.RemoteDesktopUsersSID:
					memberobject.EdgeTo(machine, EdgeLocalRDPRights)
				}

				if membersid.StripRID() == localsid || membersid.Component(2) != 21 {
					// Local user or group, we don't know - add it to computer for now
					memberobject.ChildOf(machine)
				}
			}
		}
	}

	// USERS THAT HAVE SESSIONS ON THE MACHINE ONCE IN WHILE
	for _, login := range cinfo.LoginPopularity.Day {
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
			activedirectory.ObjectSid, engine.AttributeValueSID(usersid),
			engine.ObjectCategorySimple, "Person",
		)
		if usersid.StripRID() == localsid || usersid.Component(2) != 21 {
			user.SetFlex(
				engine.DataSource, uniquesource,
			)
		}

		if !strings.HasSuffix(login.Name, "\\") {
			user.SetValues(engine.DownLevelLogonName, engine.AttributeValueString(login.Name))
		}

		machine.EdgeTo(user, EdgeLocalSessionLastDay)
	}

	for _, login := range cinfo.LoginPopularity.Week {
		usersid, err := windowssecurity.ParseStringSID(login.SID)
		if err != nil {
			ui.Warn().Msgf("Can't convert local user SID %v: %v", login.SID, err)
			continue
		}
		if usersid.Component(2) != 21 {
			continue // Not a domain SID, skip it
		}

		// Potential translation
		// usersid = MapSID(originalsid, localsid, usersid)

		user := ao.AddNew(
			activedirectory.ObjectSid, engine.AttributeValueSID(usersid),
		)
		if usersid.StripRID() == localsid || usersid.Component(2) != 21 {
			user.SetFlex(
				engine.DataSource, uniquesource,
			)
		}

		if !strings.HasSuffix(login.Name, "\\") {
			user.SetValues(engine.DownLevelLogonName, engine.AttributeValueString(login.Name))
		}

		machine.EdgeTo(user, EdgeLocalSessionLastWeek)
	}

	for _, login := range cinfo.LoginPopularity.Month {
		usersid, err := windowssecurity.ParseStringSID(login.SID)
		if err != nil {
			ui.Warn().Msgf("Can't convert local user SID %v: %v", login.SID, err)
			continue
		}
		if usersid.Component(2) != 21 {
			continue // Not a domain SID, skip it
		}

		// Potential translation
		// usersid = MapSID(originalsid, localsid, usersid)

		user := ao.AddNew(
			activedirectory.ObjectSid, engine.AttributeValueSID(usersid),
		)
		if usersid.StripRID() == localsid || usersid.Component(2) != 21 {
			user.SetFlex(
				engine.DataSource, uniquesource,
			)
		}

		if !strings.HasSuffix(login.Name, "\\") {
			user.SetValues(engine.DownLevelLogonName, engine.AttributeValueString(login.Name))
		}

		machine.EdgeTo(user, EdgeLocalSessionLastMonth)
	}

	// AUTOLOGIN CREDENTIALS - ONLY IF DOMAIN JOINED AND IT'S TO THIS DOMAIN
	if cinfo.Machine.DefaultUsername != "" &&
		cinfo.Machine.DefaultDomain != "" &&
		strings.EqualFold(cinfo.Machine.DefaultDomain, cinfo.Machine.Domain) {
		// NETBIOS name for domain check FIXME
		user, _ := ao.FindOrAdd(
			engine.NetbiosDomain, engine.AttributeValueString(cinfo.Machine.DefaultDomain),
			activedirectory.SAMAccountName, cinfo.Machine.DefaultUsername,
			engine.DownLevelLogonName, cinfo.Machine.DefaultDomain+"\\"+cinfo.Machine.DefaultUsername,
			activedirectory.ObjectCategorySimple, "Person",
		)
		machine.EdgeTo(user, EdgeHasAutoAdminLogonCredentials)
	}

	// SERVICES
	servicescontainer := engine.NewObject(activedirectory.Name, "Services")
	ao.Add(servicescontainer)
	servicescontainer.ChildOf(machine)

	// All services are a member of this group
	localservicesgroup := ao.AddNew(
		activedirectory.ObjectSid, engine.AttributeValueSID(windowssecurity.ServicesSID),
		engine.DownLevelLogonName, cinfo.Machine.Name+"\\Services",
		engine.DataSource, cinfo.Machine.Name,
	)

	for _, service := range cinfo.Services {
		serviceobject := engine.NewObject(
			engine.IgnoreBlanks,
			activedirectory.Name, service.Name,
			activedirectory.DisplayName, service.Name,
			activedirectory.Description, service.Description,
			ServiceStart, int64(service.Start),
			ServiceType, int64(service.Type),
			activedirectory.ObjectCategorySimple, "Service",
		)

		ao.Add(serviceobject)
		serviceobject.ChildOf(servicescontainer)

		serviceobject.EdgeTo(localservicesgroup, engine.EdgeMemberOfGroup)

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
				activedirectory.ObjectSid, engine.AttributeValueSID(serviceaccountSID),
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

			}
			if serviceaccountSID.Component(2) < 21 {
				svcaccount.SetFlex(activedirectory.ObjectCategorySimple, "Group")
			}
		}
		if svcaccount == nil {
			if service.Account != "" {
				nameparts := strings.Split(service.Account, "\\")
				// account can be USER, .\USER, DOMAIN\USER (come on!)
				if len(nameparts) == 2 && (nameparts[0] == "." || strings.EqualFold(nameparts[0], cinfo.Machine.Domain)) {
					svcaccount, _ = ao.FindOrAdd(
						engine.DownLevelLogonName, engine.AttributeValueString(cinfo.Machine.Domain+"\\"+nameparts[1]),
					)
					svcaccount.SetFlex(engine.DataSource, uniquesource)
				} else if len(nameparts) == 1 {
					// no \\ in name, just a user name!? this COULD be wrong, might be a DOMAIN account?
					svcaccount, _ = ao.FindOrAdd(
						engine.DownLevelLogonName, engine.AttributeValueString(cinfo.Machine.Domain+"\\"+nameparts[0]),
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

		// Change service executable via registry
		if service.RegistryOwner != "" {
			ro, err := windowssecurity.ParseStringSID(service.RegistryOwner)
			if err == nil {
				o := ao.AddNew(
					activedirectory.ObjectSid, engine.AttributeValueSID(ro),
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
				if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && (entry.ACEFlags&engine.AceFlagsInheritOnly) == 0 {
					if entrysid == windowssecurity.AdministratorsSID || entrysid == windowssecurity.SystemSID || entrysid.Component(2) == 80 /* Service user */ {
						// if we have local admin it's already game over so don't map this
						continue
					}

					var o *engine.Object

					if entrysid == windowssecurity.SystemSID {
						o = machine
					} else {
						o = ao.AddNew(
							activedirectory.ObjectSid, engine.AttributeValueSID(entrysid),
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
			engine.ObjectCategorySimple, "Executable",
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
				activedirectory.ObjectSid, engine.AttributeValueSID(ownersid),
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
						activedirectory.ObjectSid, engine.AttributeValueSID(entrysid),
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

	// Privileges to exploits - from https://github.com/gtworek/Priv2Admin
	for _, pi := range cinfo.Privileges {
		var pwn engine.Edge
		switch pi.Name {
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
		case "SeTcbPrivilege":
			pwn = EdgeSeTcb
		default:
			continue
		}

		for _, sidstring := range pi.AssignedSIDs {
			sid, err := windowssecurity.ParseStringSID(sidstring)
			if err != nil {
				ui.Error().Msgf("Invalid SID %v: %v", sidstring, err)
				continue
			}

			// Only domain users for now
			if sid.Component(2) != 21 && sid != windowssecurity.LocalServiceSID && sid != windowssecurity.NetworkServiceSID && sid != windowssecurity.ServicesSID {
				continue
			}

			// Potential translation
			// sid = MapSID(originalsid, localsid, sid)
			assignee := ao.AddNew(
				activedirectory.ObjectSid, engine.AttributeValueSID(sid),
			)
			if sid.StripRID() == localsid || sid.Component(2) != 21 {
				assignee.SetFlex(
					engine.DataSource, uniquesource,
				)
			}

			assignee.EdgeTo(machine, pwn)
		}
	}

	// SHARES
	if len(cinfo.Shares) > 0 {
		computershares := ao.AddNew(
			activedirectory.ObjectCategorySimple, "Container",
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
				engine.ObjectCategorySimple, "Share",
			)

			machine.EdgeTo(shareobject, EdgeShares)

			shareobject.ChildOf(computershares)

			// Fileshare rights
			if sd, err := engine.ParseSecurityDescriptor(share.DACL); err == nil {
				// if !sd.Owner.IsNull() {
				// 	ui.Warn().Msgf("Share %v has owner set to %v", share.Name, sd.Owner)
				// }
				// if !sd.Group.IsNull() {
				// 	ui.Warn().Msgf("Share %v has group set to %v", share.Name, sd.Group)
				// }
				for _, entry := range sd.DACL.Entries {
					if entry.Type == engine.ACETYPE_ACCESS_ALLOWED {
						entrysid := entry.SID
						o := ao.AddNew(
							activedirectory.ObjectSid, engine.AttributeValueSID(entrysid),
						)
						if entrysid.StripRID() == localsid || entrysid.Component(2) != 21 {
							o.SetFlex(
								engine.DataSource, uniquesource,
							)
						}
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
			}

			pathobject := ao.AddNew(
				engine.IgnoreBlanks,
				activedirectory.DisplayName, share.Path,
				AbsolutePath, share.Path,
				engine.ObjectCategorySimple, "Directory",
			)

			pathobject.ChildOf(machine)

			shareobject.EdgeTo(pathobject, EdgePublishes)

			// File rights
			if sd, err := engine.ParseSecurityDescriptor(share.PathDACL); err == nil {
				if !sd.Owner.IsNull() {
					owner := ao.AddNew(
						activedirectory.ObjectSid, engine.AttributeValueSID(sd.Owner),
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
							activedirectory.ObjectSid, engine.AttributeValueSID(entrysid),
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
			activedirectory.ObjectSid, engine.AttributeValueSID(windowssecurity.EveryoneSID),
			engine.DataSource, engine.AttributeValueString(cinfo.Machine.Domain),
		)

		// Everyone who is a member of the Domain is also a member of "our" Everyone
		domaineveryoneobject.EdgeTo(everyoneobject, activedirectory.EdgeMemberOfGroup)

		domainauthenticatedusers := ao.AddNew(
			activedirectory.ObjectSid, engine.AttributeValueSID(windowssecurity.AuthenticatedUsersSID),
			engine.DataSource, engine.AttributeValueString(cinfo.Machine.Domain),
		)

		domainauthenticatedusers.EdgeTo(authenticatedusers, activedirectory.EdgeMemberOfGroup)
	}

	return machine, nil
}
