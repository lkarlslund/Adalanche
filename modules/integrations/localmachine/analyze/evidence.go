package analyze

import (
	"encoding/json"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

var LocalEvidence = engine.NewAttribute("localMachineEvidence")

// LocalEvidenceCapture retains typed observations without creating inventory nodes.
// Command arguments, task XML and embedded script data are intentionally omitted.
type LocalEvidenceCapture struct {
	Captured     time.Time
	Software     []lm.Software
	Logins       []lm.LogonInfo
	Privileges   lm.Privileges
	Availability lm.Availability
	Services     []ServiceEvidence
	Tasks        []TaskEvidence
}
type ServiceEvidence struct {
	Name, Executable, AccountSID string
	Start, Type                  int
	RequiredPrivileges           []string
}
type TaskEvidence struct {
	Name, Path, UserID  string
	Enabled             bool
	LogonType, RunLevel int
	Triggers            []string
}

func importLocalEvidence(machine *engine.Node, info lm.Info) error {
	e := LocalEvidenceCapture{Captured: info.Collected, Software: info.Software, Logins: info.LoginInfos, Privileges: info.Privileges, Availability: info.Availability}
	for _, s := range info.Services {
		e.Services = append(e.Services, ServiceEvidence{s.Name, s.ImageExecutable, s.AccountSID, s.Start, s.Type, s.RequiredPrivileges})
	}
	for _, t := range info.Tasks {
		e.Tasks = append(e.Tasks, TaskEvidence{t.Name, t.Path, t.Definition.Principal.UserID, t.Enabled, t.Definition.Principal.LogonType, t.Definition.Principal.RunLevel, t.Definition.Triggers})
	}
	// Software uninstall commands and help/contact fields are not needed by analysis.
	e.Software = append([]lm.Software(nil), info.Software...)
	for i := range e.Software {
		e.Software[i].UninstallString = ""
		e.Software[i].HelpLink = ""
		e.Software[i].Contact = ""
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	machine.SetFlex(LocalEvidence, string(raw))
	return nil
}
