package main

import (
	"encoding/xml"
	"regexp"
	"strings"

	"github.com/go-ini/ini"
	"github.com/rs/zerolog/log"
	"golang.org/x/text/encoding/unicode"
)

type ScheduledTasks struct {
	Tasks []TaskV2 `xml:TaskV2`
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
	Members Members
}

type Members struct {
	Member []Member
}

type Member struct {
	// XMLName xml.Name `xml:"Member"`
	Name   string `xml:"name,attr"`
	Action string `xml:"action,attr"`
	SID    string `xml:"sid,attr"`
}

type SIDpair struct {
	Group  string
	Member string
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
								Group:  prop.SID,
								Member: member.SID,
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
				member := strings.TrimSuffix(k, "__Memberof")
				if !strings.HasPrefix(member, "*") {
					log.Warn().Msgf("GPO GptTmplInf Memberof non-SID member %v ignored", member)
					continue
				}
				// membersid, err := SIDFromString(strings.Trim(member[1:], " "))
				// if err != nil {
				// 	log.Warn().Msgf("GPO GptTmplInf Memberof SID member %v parsing failed", member)
				// 	continue
				// }
				groups := strings.Split(v, ",")
				for _, group := range groups {
					if !strings.HasPrefix(group, "*") {
						log.Warn().Msgf("GPO GptTmplInf Memberof non-SID group %v ignored", group)
						continue
					}
					// groupsid, err := SIDFromString(strings.Trim(group[1:], " "))
					// if err != nil {
					// 	log.Warn().Msgf("GPO GptTmplInf Memberof SID group %v parsing failed", group)
					// 	continue
					// }

					results = append(results, SIDpair{
						Group:  strings.Trim(group[1:], " "),
						Member: strings.Trim(member[1:], " "),
					})
				}
			} else if strings.HasSuffix(k, "__Members") {
				// LHS SID group has RHS SID as members
				group := strings.TrimSuffix(k, "__Members")
				if !strings.HasPrefix(group, "*") {
					log.Warn().Msgf("GPO GptTmplInf Members non-SID group %v ignored", group)
					continue
				}

				members := strings.Split(v, ",")
				for _, member := range members {
					if !strings.HasPrefix(member, "*") {
						log.Warn().Msgf("GPO GptTmplInf Members non-SID member %v ignored", member)
						continue
					}
					// groupsid, err := SIDFromString(strings.Trim(group[1:], " "))
					// if err != nil {
					// 	log.Warn().Msgf("GPO GptTmplInf Memberof SID group %v parsing failed", group)
					// 	continue
					// }

					results = append(results, SIDpair{
						Group:  strings.Trim(group[1:], " "),
						Member: strings.Trim(member[1:], " "),
					})
				}
			}
		}
	}
	return results
}
