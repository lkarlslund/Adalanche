package analyze

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/rs/zerolog/log"
)

var (
	LocalMachineSID = engine.A("LocalMachineSID")

	PwnLocalAdminRights             = engine.NewPwn("AdminRights")
	PwnLocalRDPRights               = engine.NewPwn("RDPRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 30 })
	PwnLocalDCOMRights              = engine.NewPwn("DCOMRights").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 50 })
	PwnLocalSMSAdmins               = engine.NewPwn("SMSAdmins").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 50 })
	PwnLocalSessionLastDay          = engine.NewPwn("SessionLastDay").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 80 })
	PwnLocalSessionLastWeek         = engine.NewPwn("SessionLastWeek").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 55 })
	PwnLocalSessionLastMonth        = engine.NewPwn("SessionLastMonth").RegisterProbabilityCalculator(func(source, target *engine.Object) engine.Probability { return 30 })
	PwnHasServiceAccountCredentials = engine.NewPwn("SvcAccntCreds")
	PwnHasAutoAdminLogonCredentials = engine.NewPwn("AutoAdminLogonCreds")
	PwnRunsExecutable               = engine.NewPwn("RunsExecutable")
	PwnHosts                        = engine.NewPwn("Hosts")
	PwnRunsAs                       = engine.NewPwn("RunsAs")
	PwnExecuted                     = engine.NewPwn("Executed")
	PwnFileOwner                    = engine.NewPwn("FileOwner")
	PwnFileTakeOwnership            = engine.NewPwn("FileTakeOwnership")
	PwnFileWrite                    = engine.NewPwn("FileWrite")
	PwnFileModifyDACL               = engine.NewPwn("FileModifyDACL")
	PwnRegistryWrite                = engine.NewPwn("RegistryWrite")
	PwnRegistryModifyDACL           = engine.NewPwn("RegistryModifyDACL")
)

func ImportCollectorInfo(cinfo localmachine.Info, ao *engine.Objects) error {
	var computerobject *engine.Object
	var existing bool
	if cinfo.Machine.ComputerDomainSID != "" {
		csid, err := windowssecurity.SIDFromString(cinfo.Machine.ComputerDomainSID)
		if err == nil {
			computerobject, existing = ao.FindOrAdd(
				engine.ObjectSid, engine.AttributeValueSID(csid),
			)
		}
	}

	if computerobject != nil && existing {
		// It's a duplicate domain member SID :-(
		return fmt.Errorf("duplicate machine info for domain account SID %v found, not loading it. machine names %v and %v", cinfo.Machine.ComputerDomainSID, cinfo.Machine.Name, computerobject.Label())
	}

	if computerobject == nil {
		computerobject, _ = ao.FindOrAdd(
			engine.SAMAccountName, engine.AttributeValueString(strings.ToUpper(cinfo.Machine.Name)+"$"),
		)
	} else {
		computerobject.SetAttr(
			engine.SAMAccountName, engine.AttributeValueString(strings.ToUpper(cinfo.Machine.Name)+"$"),
		)
	}

	if cinfo.Machine.IsDomainJoined {
		computerobject.SetAttr(engine.DownLevelLogonName, engine.AttributeValueString(cinfo.Machine.Domain+"\\"+cinfo.Machine.Name+"$"))
	}

	// See if the machine has a unique SID
	localsid, err := windowssecurity.SIDFromString(cinfo.Machine.LocalSID)
	if err != nil {
		return fmt.Errorf("Collected machine information doesn't contain valid local machine SID (%v): %v", cinfo.Machine.LocalSID, err)
	}
	originalsid := localsid
	for _, found := ao.Find(LocalMachineSID, engine.AttributeValueSID(localsid)); found; {
		localsid, _ = windowssecurity.SIDFromString("S-1-5-555-" + strconv.FormatUint(uint64(rand.Int31()), 10) + "-" + strconv.FormatUint(uint64(rand.Int31()), 10) + "-" + strconv.FormatUint(uint64(rand.Int31()), 10))
		log.Debug().Msgf("Local machine SID collision, trying this random SID %v")
	}
	computerobject.SetAttr(LocalMachineSID, engine.AttributeValueSID(localsid))

	ao.ReindexObject(computerobject) // We changed stuff after adding it

	// Add local accounts as synthetic objects
	userscontainer := engine.NewObject(engine.Name, engine.AttributeValueString("Users"))
	ao.Add(userscontainer)
	userscontainer.ChildOf(computerobject)
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
		usid, err := windowssecurity.SIDFromString(user.SID)
		if err == nil {
			if localsid != originalsid && usid.StripRID() == originalsid {
				// Replace SID
				usid = localsid.AddComponent(usid.RID())
			}
			user, found := ao.FindOrAdd(
				engine.ObjectSid, engine.AttributeValueSID(usid),
				engine.ObjectCategorySimple, engine.AttributeValueString("Person"),
				engine.DisplayName, engine.AttributeValueString(user.FullName),
				engine.Name, engine.AttributeValueString(user.Name),
				engine.UserAccountControl, engine.AttributeValueInt(uac),
				engine.PwdLastSet, engine.AttributeValueTime(user.PasswordLastSet),
				engine.LastLogon, engine.AttributeValueTime(user.LastLogon),
				// engine.SAMAccountName, engine.AttributeValueString(user.Name), // Clashes with AD, and needs a redesign when handling multiple domains FIXME
				engine.DownLevelLogonName, engine.AttributeValueString(cinfo.Machine.Name+"\\"+user.Name),
				engine.BadPwdCount, engine.AttributeValueInt(user.BadPasswordCount),
				engine.LogonCount, engine.AttributeValueInt(user.NumberOfLogins),
			)
			if !found {
				user.ChildOf(userscontainer)
			} else {
				log.Debug().Msgf("Duplicate local user %v with SID %v", user.Label(), usid.String())
			}
		} else {
			log.Warn().Msgf("Invalid user SID in dump: %v", user.SID)
		}
	}

	// Iterate over Groups
	groupscontainer := engine.NewObject(engine.Name, engine.AttributeValueString("Groups"))
	ao.Add(groupscontainer)
	groupscontainer.ChildOf(computerobject)
	for _, group := range cinfo.Groups {

		groupsid, err := windowssecurity.SIDFromString(group.SID)
		if localsid != originalsid && groupsid.StripRID() == originalsid {
			// Replace SID
			groupsid = localsid.AddComponent(groupsid.RID())
		}

		if err != nil && group.Name != "SMS Admins" {
			log.Warn().Msgf("Can't convert local group SID %v: %v", group.SID, err)
			continue
		}
		for _, member := range group.Members {
			var membersid windowssecurity.SID
			if member.SID != "" {
				membersid, err = windowssecurity.SIDFromString(member.SID)
				if err != nil {
					log.Warn().Msgf("Can't convert local group member SID %v: %v", member.SID, err)
					continue
				}
			} else {
				// Some members show up with the SID in the name field FML
				membersid, err = windowssecurity.SIDFromString(member.Name)
				if err != nil {
					log.Info().Msgf("Fallback SID translation on %v failed: %v", member.Name, err)
					continue
				}
			}

			if membersid.Component(2) != 21 {
				continue // Not a local or domain SID, skip it
			}

			if localsid != originalsid && membersid.StripRID() == originalsid {
				// Replace SID
				membersid = localsid.AddComponent(membersid.RID())
			}

			var memberobject *engine.Object
			var found bool
			switch {
			case group.Name == "SMS Admins":
				memberobject, found = ao.FindOrAdd(
					engine.ObjectSid, engine.AttributeValueSID(membersid),
					engine.DownLevelLogonName, engine.AttributeValueString(member.Name),
				)
				memberobject.Pwns(computerobject, PwnLocalSMSAdmins)
			case groupsid == windowssecurity.SIDAdministrators:
				memberobject, found = ao.FindOrAdd(
					engine.ObjectSid, engine.AttributeValueSID(membersid),
					engine.DownLevelLogonName, engine.AttributeValueString(member.Name),
				)
				memberobject.Pwns(computerobject, PwnLocalAdminRights)
			case groupsid == windowssecurity.SIDDCOMUsers:
				memberobject, found = ao.FindOrAdd(
					engine.ObjectSid, engine.AttributeValueSID(membersid),
					engine.DownLevelLogonName, engine.AttributeValueString(member.Name),
				)
				memberobject.Pwns(computerobject, PwnLocalDCOMRights)
			case groupsid == windowssecurity.SIDRemoteDesktopUsers:
				memberobject, found = ao.FindOrAdd(
					engine.ObjectSid, engine.AttributeValueSID(membersid),
					engine.DownLevelLogonName, engine.AttributeValueString(member.Name),
				)
				memberobject.Pwns(computerobject, PwnLocalRDPRights)
			}

			if memberobject != nil && !found {
				if membersid.StripRID() == localsid {
					// Local user or group, we don't know - add it to computer for now
					memberobject.ChildOf(computerobject)
				}
			}
		}
	}

	// USERS THAT HAVE SESSIONS ON THE MACHINE ONCE IN WHILE
	for _, login := range cinfo.LoginPopularity.Day {
		usersid, err := windowssecurity.SIDFromString(login.SID)
		if err != nil {
			log.Warn().Msgf("Can't convert local user SID %v: %v", login.SID, err)
			continue
		}
		if usersid.Component(2) != 21 {
			continue // Not a local or domain SID, skip it
		}

		if localsid != originalsid && usersid.StripRID() == originalsid {
			// Replace SID
			usersid = localsid.AddComponent(usersid.RID())
		}

		user, _ := ao.FindOrAdd(
			engine.ObjectSid, engine.AttributeValueSID(usersid),
			engine.DownLevelLogonName, engine.AttributeValueString(login.Name),
		)
		computerobject.Pwns(user, PwnLocalSessionLastDay)
	}

	for _, login := range cinfo.LoginPopularity.Week {
		usersid, err := windowssecurity.SIDFromString(login.SID)
		if err != nil {
			log.Warn().Msgf("Can't convert local user SID %v: %v", login.SID, err)
			continue
		}
		if usersid.Component(2) != 21 {
			continue // Not a domain SID, skip it
		}

		if localsid != originalsid && usersid.StripRID() == originalsid {
			// Replace SID
			usersid = localsid.AddComponent(usersid.RID())
		}

		user, _ := ao.FindOrAdd(
			engine.ObjectSid, engine.AttributeValueSID(usersid),
			engine.DownLevelLogonName, engine.AttributeValueString(login.Name),
		)
		computerobject.Pwns(user, PwnLocalSessionLastWeek)
	}

	for _, login := range cinfo.LoginPopularity.Month {
		usersid, err := windowssecurity.SIDFromString(login.SID)
		if err != nil {
			log.Warn().Msgf("Can't convert local user SID %v: %v", login.SID, err)
			continue
		}
		if usersid.Component(2) != 21 {
			continue // Not a domain SID, skip it
		}

		if localsid != originalsid && usersid.StripRID() == originalsid {
			// Replace SID
			usersid = localsid.AddComponent(usersid.RID())
		}

		user, _ := ao.FindOrAdd(
			engine.ObjectSid, engine.AttributeValueSID(usersid),
			engine.DownLevelLogonName, engine.AttributeValueString(login.Name),
		)
		computerobject.Pwns(user, PwnLocalSessionLastMonth)
	}

	// AUTOLOGIN CREDENTIALS - ONLY IF DOMAIN JOINED AND IT'S TO THIS DOMAIN
	if cinfo.Machine.DefaultUsername != "" &&
		cinfo.Machine.DefaultDomain != "" &&
		cinfo.Machine.IsDomainJoined &&
		cinfo.Machine.DefaultDomain == cinfo.Machine.Domain {
		// NETBIOS name for domain check FIXME
		user, _ := ao.FindOrAdd(
			engine.NetbiosDomain, engine.AttributeValueString(cinfo.Machine.DefaultDomain),
			engine.SAMAccountName, engine.AttributeValueString(cinfo.Machine.DefaultUsername),
			engine.DownLevelLogonName, engine.AttributeValueString(cinfo.Machine.DefaultDomain+"\\"+cinfo.Machine.DefaultUsername),
			engine.ObjectCategorySimple, engine.AttributeValueString("Person"),
		)
		computerobject.Pwns(user, PwnHasAutoAdminLogonCredentials)
	}

	// SERVICES
	servicescontainer := engine.NewObject(engine.Name, engine.AttributeValueString("Services"))
	ao.Add(servicescontainer)
	servicescontainer.ChildOf(computerobject)

	for _, service := range cinfo.Services {
		serviceobject := engine.NewObject(
			engine.DisplayName, engine.AttributeValueString(service.Name),
			engine.ObjectCategorySimple, engine.AttributeValueString("Service"),
		)
		ao.Add(serviceobject)
		serviceobject.ChildOf(servicescontainer)
		computerobject.Pwns(serviceobject, PwnHosts)

		if serviceaccountSID, err := windowssecurity.SIDFromString(service.AccountSID); err == nil && serviceaccountSID.Component(2) == 21 {

			if localsid != originalsid && serviceaccountSID.StripRID() == originalsid {
				// Replace SID
				serviceaccountSID = localsid.AddComponent(serviceaccountSID.RID())
			}

			nameparts := strings.Split(service.Account, "\\")
			if len(nameparts) == 2 && nameparts[0] != cinfo.Machine.Domain { // FIXME - NETBIOS NAMES ARE KILLIG US
				svcaccount, _ := ao.FindOrAdd(
					engine.ObjectSid, engine.AttributeValueSID(serviceaccountSID),
					engine.SAMAccountName, engine.AttributeValueString(nameparts[1]),
					engine.ObjectCategorySimple, engine.AttributeValueString("Person"),
				)

				computerobject.Pwns(svcaccount, PwnHasServiceAccountCredentials)
				serviceobject.Pwns(svcaccount, PwnRunsAs)
			}
		}

		// Change service executable via registry
		if sd, err := engine.ParseACL(service.RegistryDACL); err == nil {
			for _, entry := range sd.Entries {
				entrysid := entry.SID
				if entry.Type&engine.ACETYPE_ACCESS_ALLOWED != 0 && entrysid.Component(2) == 21 {

					if localsid != originalsid && entrysid.StripRID() == originalsid {
						// Replace SID
						entrysid = localsid.AddComponent(entrysid.RID())
					}

					o, _ := ao.FindOrAdd(
						engine.ObjectSid, engine.AttributeValueSID(entrysid),
					)

					if entry.Mask&engine.KEY_SET_VALUE != engine.KEY_SET_VALUE {
						o.Pwns(serviceobject, PwnRegistryWrite)
					}

					if entry.Mask&engine.RIGHT_WRITE_DACL != engine.RIGHT_WRITE_DACL {
						o.Pwns(serviceobject, PwnRegistryModifyDACL)
					}
				}
			}
			// log.Debug().Msgf("%v registr %v", service.Name, sd)
		}

		// Change service executable contents
		serviceimageobject := engine.NewObject(
			engine.DisplayName, engine.AttributeValueString(filepath.Base(service.ImageExecutable)),
			engine.ObjectClass, engine.AttributeValueString("Executable"),
		)
		ao.Add(serviceimageobject)
		serviceimageobject.Pwns(serviceobject, PwnExecuted)
		serviceimageobject.ChildOf(serviceobject)

		if ownersid, err := windowssecurity.SIDFromString(service.ImageExecutableOwner); err == nil {
			if localsid != originalsid && ownersid.StripRID() == originalsid {
				// Replace SID
				ownersid = localsid.AddComponent(ownersid.RID())
			}

			owner, _ := ao.FindOrAdd(
				engine.ObjectSid, engine.AttributeValueSID(ownersid),
			)
			owner.Pwns(serviceobject, PwnFileOwner)
		}

		if sd, err := engine.ParseACL(service.ImageExecutableDACL); err == nil {
			for _, entry := range sd.Entries {
				entrysid := entry.SID
				if entry.Type&engine.ACETYPE_ACCESS_ALLOWED != 0 && entrysid.Component(2) == 21 {
					if localsid != originalsid && entrysid.StripRID() == originalsid {
						// Replace SID
						entrysid = localsid.AddComponent(entrysid.RID())
					}

					o, _ := ao.FindOrAdd(
						engine.ObjectSid, engine.AttributeValueSID(entrysid),
					)
					if entry.Mask&engine.FILE_WRITE_DATA != engine.FILE_WRITE_DATA {
						o.Pwns(serviceimageobject, PwnFileWrite)
					}
					if entry.Mask&engine.RIGHT_WRITE_OWNER != engine.RIGHT_WRITE_OWNER {
						o.Pwns(serviceimageobject, PwnFileTakeOwnership) // Not sure about this one
					}
					if entry.Mask&engine.RIGHT_WRITE_DACL != engine.RIGHT_WRITE_DACL {
						o.Pwns(serviceimageobject, PwnFileModifyDACL)
					}
				}
			}
			// log.Debug().Msgf("Service %v executable %v: %v", service.Name, service.ImageExecutable, sd)
		}
	}

	// MACHINE AVAILABILITY

	// SOFTWARE INVENTORY AS ATTRIBUTES
	installedsoftware := make(engine.AttributeValueSlice, len(cinfo.Software))
	for i, software := range cinfo.Software {
		installedsoftware[i] = engine.AttributeValueString(fmt.Sprintf(
			"%v %v %v", software.Publisher, software.DisplayName, software.DisplayVersion,
		))
	}
	if len(installedsoftware) > 0 {
		computerobject.Set(engine.A("_InstalledSoftware"), installedsoftware)
	}
	return nil
}
