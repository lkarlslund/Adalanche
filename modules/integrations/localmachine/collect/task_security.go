package collect

import (
	"encoding/json"
	"strings"

	"github.com/lkarlslund/adalanche/modules/basedata"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

func applyTaskSecurity(info *lm.Info, capture lm.AssessmentCapture) {
	if info.CollectionResults == nil {
		info.CollectionResults = basedata.CollectionResults{}
	}
	info.CollectionResults["tasks/security-enumerate"] = capture.Result
	indices := make(map[string]int, len(info.Tasks))
	for i, t := range info.Tasks {
		indices[strings.ToLower(t.Path)] = i
	}
	for _, raw := range capture.Records {
		var record struct {
			Path, SDDL string
			Result     basedata.CollectionResult
		}
		if json.Unmarshal(raw, &record) != nil {
			continue
		}
		i, ok := indices[strings.ToLower(record.Path)]
		if !ok {
			continue
		}
		info.CollectionResults["tasks/security/"+info.Tasks[i].Path] = record.Result
		if record.Result.Status == basedata.CollectionCollected && record.Result.ErrorCode == "" && record.SDDL != "" {
			info.Tasks[i].Definition.RegistrationInfo.SecurityDescriptor = record.SDDL
		}
	}
}
