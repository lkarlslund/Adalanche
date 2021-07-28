package main

import (
	"encoding/xml"
	"regexp"
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
	uncexec       = regexp.MustCompile(`\\\\.*\\.*\.(cmd|bat|ps1|vbs|exe|dll)`)
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

// SID added to
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
