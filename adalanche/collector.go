package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/lkarlslund/adalanche/modules/collector"
	"github.com/rs/zerolog/log"
)

func importCollectorFiles(path string, objs *Objects) error {
	filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
			// Import it
			raw, err := ioutil.ReadFile(path)
			if err != nil {
				log.Warn().Msgf("Problem reading collector file %v: %v", info.Name(), err)
				return nil
			}
			var cinfo collector.Info
			err = json.Unmarshal(raw, &cinfo)
			if err != nil {
				log.Error().Msgf("Problem unmarshalling %v from JSON: %v", info.Name(), err)
				return nil // The show must go on
			}

			//			if !strings.EqualFold(objs.Domain, cinfo.Machine.Domain) {
			//				return nil // Machine is domain joined, but not to this domain!? Ignore for now
			//			}

			// find computer object
			mo := objs.Filter(func(o *Object) bool {
				return o.HasAttrValue(SAMAccountName, strings.ToUpper(cinfo.Machine.Name+"$"))
			})
			co := mo.AsArray()
			if len(co) != 1 {
				return nil // We didn't find it
			}
			computerobject := co[0]

			// Add local accounts as synthetic objects

			// Iterate over Groups
			for _, group := range cinfo.Groups {
				groupsid, err := SIDFromString(group.SID)
				if err != nil {
					log.Warn().Msgf("Can't convert local group SID %v: %v", group.SID, err)
					continue
				}
				for _, member := range group.Members {
					membersid, err := SIDFromString(member.SID)
					if err != nil {
						log.Warn().Msgf("Can't convert local group member SID %v: %v", member.SID, err)
						continue
					}
					if membersid.Component(2) != 21 {
						continue // Not a domain SID, skip it
					}
					if member, found := objs.FindSID(membersid); found {
						switch groupsid {
						case SIDAdministrators:
							member.CanPwn.Set(computerobject, PwnLocalAdminRights)
							computerobject.PwnableBy.Set(member, PwnLocalAdminRights)
						case SIDDCOMUsers:
							member.CanPwn.Set(computerobject, PwnLocalDCOMRights)
							computerobject.PwnableBy.Set(member, PwnLocalDCOMRights)
						case SIDRemoteDesktopUsers:
							member.CanPwn.Set(computerobject, PwnLocalRDPRights)
							computerobject.PwnableBy.Set(member, PwnLocalRDPRights)
						}
					}
				}
			}

			// USERS THAT HAVE SESSIONS ON THE MACHINE ONCE IN WHILE
			for _, login := range cinfo.LoginPopularity.Day {
				usersid, err := SIDFromString(login.SID)
				if err != nil {
					log.Warn().Msgf("Can't convert local user SID %v: %v", login.SID, err)
					continue
				}
				if usersid.Component(2) != 21 {
					continue // Not a domain SID, skip it
				}
				if user, found := objs.FindSID(usersid); found {
					computerobject.CanPwn.Set(user, PwnLocalSessionLastDay)
					user.PwnableBy.Set(computerobject, PwnLocalSessionLastDay)
				}
			}
			for _, login := range cinfo.LoginPopularity.Week {
				usersid, err := SIDFromString(login.SID)
				if err != nil {
					log.Warn().Msgf("Can't convert local user SID %v: %v", login.SID, err)
					continue
				}
				if usersid.Component(2) != 21 {
					continue // Not a domain SID, skip it
				}
				if user, found := objs.FindSID(usersid); found {
					computerobject.CanPwn.Set(user, PwnLocalSessionLastWeek)
					user.PwnableBy.Set(computerobject, PwnLocalSessionLastWeek)
				}
			}
			for _, login := range cinfo.LoginPopularity.Month {
				usersid, err := SIDFromString(login.SID)
				if err != nil {
					log.Warn().Msgf("Can't convert local user SID %v: %v", login.SID, err)
					continue
				}
				if usersid.Component(2) != 21 {
					continue // Not a domain SID, skip it
				}
				if user, found := objs.FindSID(usersid); found {
					computerobject.CanPwn.Set(user, PwnLocalSessionLastMonth)
					user.PwnableBy.Set(computerobject, PwnLocalSessionLastMonth)
				}
			}

		}
		return nil
	})

	return nil // FIXME
}
