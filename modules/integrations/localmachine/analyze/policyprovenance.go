package analyze

import (
	"encoding/json"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

// importPolicyProvenance records what the machine reports about its own
// policy processing: the AD site it placed itself in, and the GPOs applied
// to the computer according to its cached policy results. Each applied GPO
// becomes a node keyed only by its SYSVOL path (gPCFileSysPath), which the
// merge folds into the directory's GPO object; GPOs from domains that were
// not collected stay visible on their own.
func importPolicyProvenance(ao *engine.IndexedGraph, machine *engine.Node, info lm.Info) {
	if info.AssessmentData == "" {
		return
	}
	assessment, err := lm.DecodeAssessment(info.AssessmentData)
	if err != nil {
		return
	}
	for _, raw := range assessment.Categories["policy-provenance"].Records {
		var r struct {
			Class           string
			Scope           string
			SiteName        string
			DynamicSiteName string
			Name            string `json:"name"`
			GUIDName        string `json:"guidName"`
			FileSystemPath  string `json:"fileSystemPath"`
			Enabled         bool   `json:"enabled"`
			AccessDenied    bool   `json:"accessDenied"`
			FilterAllowed   bool   `json:"filterAllowed"`
		}
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		switch r.Class {
		case "MachineSite":
			// An administrator override wins over the discovered site.
			if site := r.SiteName; site != "" {
				machine.Set(lm.ADSite, engine.NV(site))
			} else if r.DynamicSiteName != "" {
				machine.Set(lm.ADSite, engine.NV(r.DynamicSiteName))
			}
		case "RSOP_GPO":
			if r.Scope != "machine" {
				continue
			}
			// Results were collected; they replace inferred GPO targeting.
			machine.Set(lm.GPOResultsCollected, engine.NV(true))
			if !r.Enabled || r.AccessDenied || !r.FilterAllowed {
				continue
			}
			path := gpoSysvolPath(r.FileSystemPath)
			if path == "" {
				continue // the local policy has no SYSVOL path
			}
			// No distinguished name or data source: either would make the
			// merge treat this as the authoritative object.
			gpo, _ := ao.FindOrAdd(activedirectory.GPCFileSysPath, engine.NV(path),
				engine.IgnoreBlanks,
				engine.Type, engine.NodeTypeGroupPolicyContainer.ValueString(),
				engine.Name, engine.NV(r.GUIDName),
				engine.DisplayName, engine.NV(r.Name),
			)
			ao.EdgeTo(gpo, machine, activedirectory.EdgeAffectedByGPO)
		}
	}
}

// gpoSysvolPath turns a GPO path from policy results into the form of
// gPCFileSysPath: the GPO's SYSVOL folder without a Machine or User part.
func gpoSysvolPath(path string) string {
	path = strings.TrimRight(path, `\`)
	lower := strings.ToLower(path)
	for _, part := range []string{`\machine`, `\user`} {
		if strings.HasSuffix(lower, part) {
			path = path[:len(path)-len(part)]
			break
		}
	}
	if !strings.HasPrefix(path, `\\`) {
		return ""
	}
	return path
}
