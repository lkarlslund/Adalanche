package collect

import (
	"encoding/json"
	"testing"

	"github.com/lkarlslund/adalanche/modules/basedata"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

func TestTaskSecurityAcquisition(t *testing.T) {
	info := lm.Info{Tasks: []lm.RegisteredTask{{Path: `\synthetic`}, {Path: `\denied`}}}
	applyTaskSecurity(&info, lm.AssessmentCapture{Result: basedata.CollectionResult{Status: basedata.CollectionFailed}, Records: []json.RawMessage{
		json.RawMessage(`{"Path":"\\SYNTHETIC","SDDL":"D:(A;;FA;;;SY)","Result":{"Status":"collected"}}`),
		json.RawMessage(`{"Path":"\\denied","SDDL":"D:(A;;FA;;;WD)","Result":{"Status":"access_denied"}}`),
	}})
	if info.Tasks[0].Definition.RegistrationInfo.SecurityDescriptor == "" {
		t.Fatal("lost partial success")
	}
	if info.Tasks[1].Definition.RegistrationInfo.SecurityDescriptor != "" {
		t.Fatal("used unsuccessful read")
	}
	if info.CollectionResults[`tasks/security/\denied`].Status != basedata.CollectionAccessDenied || info.CollectionResults["tasks/security-enumerate"].Status != basedata.CollectionFailed {
		t.Fatal("lost outcome")
	}
}
