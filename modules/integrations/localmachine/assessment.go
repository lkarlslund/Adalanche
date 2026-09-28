package localmachine

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
)

const AssessmentVersion = 1

// Assessment records configuration and permissions, never credential material.
// Categories and item results are independent: partial enumeration is not empty success.
type Assessment struct {
	Version    int                          `json:"version"`
	Captured   time.Time                    `json:"captured"`
	Categories map[string]AssessmentCapture `json:"categories"`
	Paths      []PathSecurity               `json:"paths,omitempty"`
}
type AssessmentCapture struct {
	Result  basedata.CollectionResult `json:"result"`
	Records []json.RawMessage         `json:"records"`
}
type PathSecurity struct {
	Path    string                    `json:"path"`
	Purpose string                    `json:"purpose"`
	Subject string                    `json:"subject"`
	Owner   string                    `json:"owner,omitempty"`
	DACL    []byte                    `json:"dacl,omitempty"`
	Result  basedata.CollectionResult `json:"result"`
}

func DecodeAssessment(raw string) (Assessment, error) {
	var data Assessment
	if raw == "" {
		return data, fmt.Errorf("assessment not collected")
	}
	if len(raw) > 32<<20 {
		return data, fmt.Errorf("assessment exceeds size limit")
	}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return data, err
	}
	if data.Version != AssessmentVersion || data.Captured.IsZero() || data.Categories == nil {
		return data, fmt.Errorf("unsupported or incomplete assessment")
	}
	return data, nil
}
