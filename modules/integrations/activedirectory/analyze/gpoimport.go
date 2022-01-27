package analyze

import (
	"encoding/xml"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-ini/ini"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"github.com/rs/zerolog/log"
	"golang.org/x/text/encoding/unicode"
)

var (
	gPCFileSysPath = engine.NewAttribute("gPCFileSysPath").Merge()

	AbsolutePath     = engine.NewAttribute("AbsolutePath")
	RelativePath     = engine.NewAttribute("RelativePath")
	PwnOwns          = engine.NewPwn("Owns")
	PwnFSPartOfGPO   = engine.NewPwn("FSPartOfGPO")
	PwnFileCreate    = engine.NewPwn("FileCreate")
	PwnDirCreate     = engine.NewPwn("DirCreate")
	PwnFileWrite     = engine.NewPwn("FileWrite")
	PwnTakeOwnership = engine.NewPwn("FileTakeOwnership")
	PwnModifyDACL    = engine.NewPwn("FileModifyDACL")
)

func init() {
	engine.AddMergeApprover(func(a, b *engine.Object) (*engine.Object, error) {
		if a.HasAttr(RelativePath) || b.HasAttr(RelativePath) {
			return nil, engine.ErrDontMerge
		}
		return nil, engine.ErrMergeOnThis
	})
}

func ImportGPOInfo(ginfo activedirectory.GPOdump, ao *engine.Objects) error {
	if ginfo.DomainDN != "" {
		ao.AddDefaultFlex(engine.UniqueSource, ginfo.DomainDN)
	}

	gpoobject, _ := ao.FindOrAdd(gPCFileSysPath, engine.AttributeValueString(ginfo.Path))

	// Pwns(gpoobject)

	for _, item := range ginfo.Files {
		relativepath := strings.ToLower(strings.ReplaceAll(item.RelativePath, "\\", "/"))
		if relativepath == "" {
			relativepath = "/"
		}

		absolutepath := filepath.Join(ginfo.Path, relativepath)

		objecttype := "File"
		if item.IsDir {
			objecttype = "Directory"
		}

		itemobject := ao.AddNew(
			AbsolutePath, engine.AttributeValueString(absolutepath),
			RelativePath, engine.AttributeValueString(relativepath),
			engine.DisplayName, engine.AttributeValueString(relativepath),
			engine.ObjectCategorySimple, engine.AttributeValueString(objecttype),
		)

		if relativepath == "/" {
			itemobject.Pwns(gpoobject, PwnFSPartOfGPO)
			gpoobject.Adopt(itemobject)
		} else {
			parentpath := filepath.Join(ginfo.Path, filepath.Dir(relativepath))
			if parentpath == "" {
				parentpath = "/"
			}

			parent, _ := ao.FindOrAdd(AbsolutePath, engine.AttributeValueString(parentpath))
			itemobject.Pwns(parent, PwnFSPartOfGPO)
			parent.Adopt(itemobject)
		}

		if !item.OwnerSID.IsNull() {
			owner, _ := ao.FindOrAdd(engine.ObjectSid, engine.AttributeValueSID(item.OwnerSID))
			owner.Pwns(itemobject, PwnOwns)
		}

		if item.DACL != nil {
			dacl, err := engine.ParseACL(item.DACL)
			if err != nil {
				return err
			}
			for _, entry := range dacl.Entries {
				entrysidobject, _ := ao.FindOrAdd(activedirectory.ObjectSid, engine.AttributeValueSID(entry.SID))

				if entry.Type == engine.ACETYPE_ACCESS_ALLOWED && entry.SID.Component(2) == 21 {
					if item.IsDir && entry.Mask&engine.FILE_ADD_FILE != 0 {
						entrysidobject.Pwns(itemobject, PwnFileCreate)
					}
					if item.IsDir && entry.Mask&engine.FILE_ADD_SUBDIRECTORY != 0 {
						entrysidobject.Pwns(itemobject, PwnDirCreate)
					}
					if !item.IsDir && entry.Mask&engine.FILE_WRITE_DATA != 0 {
						entrysidobject.Pwns(itemobject, PwnFileWrite)
					}
					if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
						entrysidobject.Pwns(itemobject, PwnTakeOwnership) // Not sure about this one
					}
					if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
						entrysidobject.Pwns(itemobject, PwnModifyDACL)
					}
				}
			}
		}

		switch relativepath {
		case "/machine/preferences/groups/groups.xml", "/machine/microsoft/windows nt/secedit/gpttmpl.inf":
			var pairs []SIDpair

			if strings.HasSuffix(relativepath, ".xml") {
				pairs = GPOparseGroups(string(item.Contents))
			} else if strings.HasSuffix(relativepath, ".inf") {
				pairs = GPOparseGptTmplInf(string(item.Contents))
			}

			for _, sidpair := range pairs {
				membersid, err := windowssecurity.SIDFromString(sidpair.MemberSID)
				if err == nil {
					switch sidpair.GroupSID {
					case "S-1-5-32-544":
						ao.FindOrAddSID(membersid).Pwns(gpoobject, activedirectory.PwnLocalAdminRights)
					case "S-1-5-32-562":
						ao.FindOrAddSID(membersid).Pwns(gpoobject, activedirectory.PwnLocalDCOMRights)
					case "S-1-5-32-555":
						ao.FindOrAddSID(membersid).Pwns(gpoobject, activedirectory.PwnLocalRDPRights)
					}
				} else {
					log.Warn().Msgf("Detected local group membership via GPO, but could not parse SID %v for member %v", sidpair.MemberSID, sidpair.MemberName)
				}
			}

			// Description: "Indicates that a GPO deploys a scheduled task which is running from an UNC path (FIXME, not done yet!)",
		case "/machine/preferences/scheduledtasks/scheduledtasks.xml":
			for _, task := range GPOparseScheduledTasks(string(item.Contents)) {
				log.Warn().Msgf("Scheduled task: %v ... FIXME!", task)
			}
		// Description: "Detects startup or shutdown scripts from GPOs",
		case "/machine/scripts/scripts.ini":
			scripts := string(item.Contents)
			utf8 := make([]byte, len(scripts)/2)
			_, _, err := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder().Transform(utf8, []byte(scripts), true)
			if err != nil {
				utf8 = []byte(scripts)
			}

			// ini.LineBreak = "\n"

			inifile, err := ini.LoadSources(ini.LoadOptions{
				SkipUnrecognizableLines: true,
			}, utf8)

			if err != nil {
				log.Warn().Msgf("Problem loading GPO ini file SCRIPTS.INI from %v: %v", ginfo.Path, err)
			}

			scriptnum := 0
			for {
				k1 := inifile.Section("Startup").Key(fmt.Sprintf("%vCmdLine", scriptnum))
				k2 := inifile.Section("Startup").Key(fmt.Sprintf("%vParameters", scriptnum))
				if k1.String() == "" {
					break
				}
				// Create new synthetic object
				sob := engine.NewObject(
					engine.ObjectCategorySimple, engine.AttributeValueString("Script"),
					engine.DistinguishedName, engine.AttributeValueString(fmt.Sprintf("CN=Startup Script %v from GPO %v,CN=synthetic", scriptnum, ginfo.GUID)),
					engine.Name, engine.AttributeValueString("Machine startup script "+strings.Trim(k1.String()+" "+k2.String(), " ")),
				)
				ao.Add(sob)
				sob.Pwns(gpoobject, activedirectory.PwnMachineScript)
				sob.ChildOf(gpoobject) // tree
				scriptnum++
			}

			scriptnum = 0
			for {
				k1 := inifile.Section("Shutdown").Key(fmt.Sprintf("%vCmdLine", scriptnum))
				k2 := inifile.Section("Shutdown").Key(fmt.Sprintf("%vParameters", scriptnum))
				if k1.String() == "" {
					break
				}
				// Create new synthetic object
				sob := engine.NewObject(
					engine.DistinguishedName, engine.AttributeValueString(fmt.Sprintf("CN=Shutdown Script %v from GPO %v,CN=synthetic", scriptnum, ginfo.GUID)),
					engine.ObjectCategorySimple, engine.AttributeValueString("Script"),
					engine.Name, engine.AttributeValueString("Machine shutdown script "+strings.Trim(k1.String()+" "+k2.String(), " ")),
				)
				ao.Add(sob)
				sob.Pwns(gpoobject, activedirectory.PwnMachineScript)
				sob.ChildOf(gpoobject)
				scriptnum++
			}
		}
	}

	return nil
}

type ScheduledTasks struct {
	Tasks []TaskV2 `xml:"TaskV2"`
}

type TaskV2 struct {
	UserID   string   `xml:"Properties>Task>Principals>Principal>UserId"`
	RunLevel string   `xml:"Properties>Task>Principals>Principal>RunLevel"`
	Actions  []Action `xml:"Properties>Task>Actions"`
}

type Action struct {
	Command   string `xml:"Exec>Command"`
	Arguments string `xml:"Exec>Arguments"`
}

var (
	uncexec       = regexp.MustCompile(`\\\\.*\\.*\\.*\.(cmd|bat|ps1|vbs|exe|dll)`)
	importantsids = regexp.MustCompile(`S-1-5-32-(544|555|562)`)
)

func GPOparseScheduledTasks(rawxml string) []string {
	var results []string
	var tasks ScheduledTasks
	err := xml.Unmarshal([]byte(rawxml), &tasks)
	if err == nil {
		for _, task := range tasks.Tasks {
			if task.RunLevel == "HighestAvailable" {
				for _, action := range task.Actions {
					cmd := action.Command + " " + action.Arguments

					// Check if we're running remote stuff
					if remoteexec := uncexec.FindAllString(cmd, -1); remoteexec != nil {
						results = append(results, remoteexec...)
					}
				}
			}
		}
	}
	return results
}

type Groups struct {
	XMLName xml.Name `xml:"Groups"`
	Group   []Group
}

type Group struct {
	XMLName    xml.Name `xml:"Group"`
	Name       string   `xml:"name,attr"`
	Properties []Properties
}

type Properties struct {
	Action  string `xml:"action,attr"`
	SID     string `xml:"groupSid,attr"`
	Name    string `xml:"groupName,attr"`
	Members Members
}

type Members struct {
	Member []Member
}

type Member struct {
	// XMLName xml.Name `xml:"Member"`
	Action string `xml:"action,attr"`
	Name   string `xml:"name,attr"`
	SID    string `xml:"sid,attr"`
}

type SIDpair struct {
	GroupSID   string
	GroupName  string
	MemberSID  string
	MemberName string
}

func GPOparseGroups(rawxml string) []SIDpair {
	var results []SIDpair
	var groups Groups
	err := xml.Unmarshal([]byte(rawxml), &groups)
	if err == nil {
		for _, group := range groups.Group {
			for _, prop := range group.Properties {
				if prop.Action == "U" && importantsids.MatchString(prop.SID) {
					for _, member := range prop.Members.Member {
						if member.Action == "ADD" {
							results = append(results, SIDpair{
								GroupSID:   prop.SID,
								GroupName:  prop.Name,
								MemberSID:  member.SID,
								MemberName: member.Name,
							})
						}
					}
				}
			}
		}
	}
	return results
}

func GPOparseGptTmplInf(rawini string) []SIDpair {
	var results []SIDpair

	utf8 := make([]byte, len(rawini)/2)
	_, _, err := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder().Transform(utf8, []byte(rawini), true)
	if err != nil {
		utf8 = []byte(rawini)
	}

	// ini.LineBreak = "\n"

	gpt, err := ini.LoadSources(ini.LoadOptions{
		SkipUnrecognizableLines: true,
	}, utf8)
	if err == nil {
		for _, key := range gpt.Section("Group Membership").Keys() {
			k := key.Name()
			v := key.String()
			if v == "" {
				// No useful data
				continue
			}
			if strings.HasSuffix(k, "__Memberof") {
				// LHS SID is member of RHS SID groups
				membersid := strings.TrimSuffix(k, "__Memberof")
				var membername string
				if strings.HasPrefix(membersid, "*") {
					// SIDs have an asterisk in front
					membersid = membersid[1:]
				} else {
					// Usernames does not
					membername = membersid
					membersid = ""
					translatedsid, err := TranslateLocalizedGroupToSID(membername)
					if err != nil {
						log.Warn().Msgf("GPO GptTmplInf Memberof non-SID member %v translation failed (PLEASE CONTRIBUTE): %v", membername, err)
					} else {
						membersid = translatedsid.String()
					}
				}
				groups := strings.Split(v, ",")
				for _, groupsid := range groups {
					var groupname string
					if strings.HasPrefix(groupsid, "*") {
						groupsid = strings.Trim(groupsid[1:], " ")
					} else {
						// Not a SID - using localized group name (thanks, Microsoft)
						// We have a couple we can try - please contribute with more
						groupname = groupsid
						groupsid = ""
						translatedsid, err := TranslateLocalizedGroupToSID(groupname)
						if err != nil {
							log.Warn().Msgf("GPO GptTmplInf Memberof non-SID group %v translation failed (PLEASE CONTRIBUTE): %v", groupname, err)
						} else {
							groupsid = translatedsid.String()
						}
					}

					results = append(results, SIDpair{
						GroupSID:   groupsid,
						GroupName:  groupname,
						MemberSID:  strings.Trim(membersid, " "),
						MemberName: strings.Trim(membername, " "),
					})
				}
			} else if strings.HasSuffix(k, "__Members") {
				// LHS SID group has RHS SID as members
				groupsid := strings.TrimSuffix(k, "__Members")
				var groupname string
				if strings.HasPrefix(groupsid, "*") {
					groupsid = strings.Trim(groupsid[1:], " ")
				} else {
					// Not a SID - using localized group name (thanks, Microsoft)
					// We have a couple we can try - please contribute with more
					groupname = groupsid
					groupsid = ""
					translatedsid, err := TranslateLocalizedGroupToSID(groupname)
					if err != nil {
						log.Warn().Msgf("GPO GptTmplInf Memberof non-SID group %v translation failed (PLEASE CONTRIBUTE): %v", groupname, err)
					} else {
						groupsid = translatedsid.String()
					}
				}

				members := strings.Split(v, ",")
				for _, membersid := range members {
					var membername string
					if strings.HasPrefix(membersid, "*") {
						membersid = membersid[1:]
					} else {
						membername = membersid
						membersid = ""
						translatedsid, err := TranslateLocalizedGroupToSID(membername)
						if err != nil {
							log.Warn().Msgf("GPO GptTmplInf Memberof non-SID member %v translation failed (PLEASE CONTRIBUTE): %v", membername, err)
						} else {
							membersid = translatedsid.String()
						}
					}
					results = append(results, SIDpair{
						GroupSID:   groupsid,
						GroupName:  groupname,
						MemberSID:  membersid,
						MemberName: membername,
					})
				}
			}
		}
	}
	return results
}
