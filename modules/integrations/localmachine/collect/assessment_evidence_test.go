package collect

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/basedata"
)

func TestTaskPayloadProjection(t *testing.T) {
	raw := `<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Principals><Principal><UserId>S-1-5-18</UserId><LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions><Exec><Command>C:\Scripts\job.ps1</Command><Arguments>not-persisted</Arguments><WorkingDirectory>C:\Scripts</WorkingDirectory></Exec><ComHandler><ClassId>{00000000-0000-0000-0000-000000000001}</ClassId><Data>secret-handler-data</Data></ComHandler></Actions><RegistrationInfo><Description>secret-description</Description></RegistrationInfo></Task>`
	task, err := parseTaskPayloads(raw)
	if err != nil || len(task.Principals) != 1 || len(task.Executables) != 1 || len(task.Handlers) != 1 {
		t.Fatalf("projection: %+v, %v", task, err)
	}
	// The schema spells this field ClassId, not ClassID.
	if task.Handlers[0].ClassID != "{00000000-0000-0000-0000-000000000001}" {
		t.Fatal("lost COM class identity")
	}
	if task.Principals[0].UserID != "S-1-5-18" {
		t.Fatal("lost task principal identity")
	}
	encoded, err := json.Marshal(task)
	if err != nil || strings.Contains(string(encoded), "secret-") {
		t.Fatalf("unrequested XML fields retained: %s, %v", encoded, err)
	}
	for _, raw := range []string{`<NotTask/>`, `<Task>`, `<Task><Actions>` + strings.Repeat(`<Exec/>`, 257) + `</Actions></Task>`, strings.Repeat("x", (1<<20)+1)} {
		if _, err := parseTaskPayloads(raw); err == nil {
			t.Fatal("accepted invalid or oversized task")
		}
	}
}

func TestTaskScriptReferences(t *testing.T) {
	for _, tt := range []struct {
		name, executable, args, want string
		unsupported                  bool
	}{
		{"file", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `-NoProfile -File "C:\Scripts\job one.ps1" -Token secret`, `C:\Scripts\job one.ps1`, false},
		{"direct", `C:\Scripts\job.vbs`, `secret`, `C:\Scripts\job.vbs`, false},
		{"script-host", `cscript.exe`, `//nologo "C:\Scripts\job.vbs" secret`, `C:\Scripts\job.vbs`, false},
		{"inline", `powershell.exe`, `-Command "secret"`, "", true},
		{"encoded", `pwsh.exe`, `-EncodedCommand secret`, "", true},
		{"missing-file", `pwsh.exe`, `-File`, "", true},
		{"switch-not-file", `pwsh.exe`, `-File -EncodedCommand secret`, "", true},
		{"unclosed", `pwsh.exe`, `-File "C:\Scripts\job.ps1`, "", true},
		{"expression", `pwsh.exe`, "-File $secret", "", true},
		{"shell", `cmd.exe`, `/c C:\Scripts\job.cmd`, "", true},
		{"ordinary-exe", `C:\App\worker.exe`, `--secret anything`, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := taskScriptPayload(tt.executable, tt.args)
			if got != tt.want || (err != nil) != tt.unsupported {
				t.Fatalf("reference = %q, %v; want %q, unsupported %v", got, err, tt.want, tt.unsupported)
			}
		})
	}
}

func TestPasswordPolicyPrecedence(t *testing.T) {
	policy := func(status basedata.CollectionStatus, settings bool) map[string]any {
		return map[string]any{"Result": basedata.CollectionResult{Status: status}, "HasExplicitSettings": settings}
	}
	absent := policy(basedata.CollectionNotFound, false)
	empty := policy(basedata.CollectionCollected, false)
	present := policy(basedata.CollectionCollected, true)
	denied := policy(basedata.CollectionAccessDenied, false)
	for _, tt := range []struct {
		name  string
		roots []map[string]any
		index int
		known bool
	}{
		{"highest", []map[string]any{present, present, present, present}, 0, true},
		{"second", []map[string]any{empty, present, present, present}, 1, true},
		{"legacy", []map[string]any{absent, empty, absent, present}, 3, true},
		{"unconfigured", []map[string]any{absent, empty, absent, empty}, -1, true},
		{"blocked", []map[string]any{denied, present, present, present}, -1, false},
		{"lower-denied", []map[string]any{present, denied, present, present}, 0, true},
		{"missing-outcome", []map[string]any{nil, present}, -1, false},
		{"enumeration-failed", []map[string]any{{"Result": basedata.CollectionResult{Status: basedata.CollectionCollected}}, present}, -1, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			index, known := selectPasswordPolicy(tt.roots)
			if index != tt.index || known != tt.known {
				t.Fatalf("selection = %d, %v; want %d, %v", index, known, tt.index, tt.known)
			}
		})
	}
	values := map[string]any{"AdministratorAccountName": basedata.CollectionResult{Status: basedata.CollectionNotFound}, "AutomaticAccountManagementEnabled": basedata.CollectionResult{Status: basedata.CollectionNotFound}}
	p := map[string]any{"ValueResults": values}
	if !passwordIdentitySettingsKnown(p, false) {
		t.Fatal("known missing settings lost")
	}
	values["AutomaticAccountManagementEnabled"] = basedata.CollectionResult{Status: basedata.CollectionAccessDenied}
	if passwordIdentitySettingsKnown(p, false) {
		t.Fatal("denied read treated as disabled automatic management")
	}
	if passwordIdentitySettingsKnown(nil, false) {
		t.Fatal("unknown settings treated as default account")
	}
}

func TestEventMetadataProjection(t *testing.T) {
	raw := `<Event><System><EventID>10005</EventID><Level>2</Level><EventRecordID>12</EventRecordID><TimeCreated SystemTime="2026-01-01T00:00:00Z"/><Correlation ActivityID="activity"/></System><EventData><Data Name="AccountName">managed</Data><Data Name="AccountSID">S-1-5-18</Data><Data Name="ErrorCode">0x80070005</Data><Data Name="Error">secret-error-text</Data><Data Name="Password">secret-password</Data><Data Name="Script">secret-script</Data></EventData></Event>`
	r, err := projectAssessmentEvent(raw, true)
	if err != nil || r["Id"] != uint32(10005) || r["ErrorCode"] != uint64(0x80070005) || r["AccountName"] != "managed" {
		t.Fatalf("event = %+v, %v", r, err)
	}
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "secret-") {
		t.Fatal("unrequested event payload retained")
	}
	r, err = projectAssessmentEvent(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := r["AccountName"]; exists {
		t.Fatal("event data retained outside password metadata scope")
	}
	if _, err := projectAssessmentEvent(`<NotEvent/>`, true); err == nil {
		t.Fatal("accepted wrong event root")
	}
}

func TestRemoteConfigurationProjection(t *testing.T) {
	r, err := projectRemoteConfiguration(`<Service><AllowUnencrypted>false</AllowUnencrypted><Auth><Basic>false</Basic><Kerberos>true</Kerberos></Auth><RootSDDL>D:(A;;GA;;;BA)</RootSDDL><RunAsPassword>secret-password</RunAsPassword></Service>`)
	if err != nil || len(r) != 4 || r["AllowUnencrypted"] != "false" || r["Kerberos"] != "true" {
		t.Fatalf("remote configuration = %+v, %v", r, err)
	}
	if _, err := projectRemoteConfiguration(`<Service><Basic>`); err == nil {
		t.Fatal("accepted incomplete XML")
	}
	if _, err := projectRemoteConfiguration(strings.Repeat("x", (1<<20)+1)); !errors.Is(err, errAssessmentLimit) {
		t.Fatal(err)
	}
}

func TestAssessmentBudgetAndTruncation(t *testing.T) {
	budget := newAssessmentBudget(2)
	budget.remaining = 16
	large := newAssessmentCapture(context.Background())
	large.budget = budget
	for large.add(strings.Repeat("x", 1024)) == nil {
	}
	if large.bytes < assessmentReserve-1100 || large.bytes > assessmentReserve+16 {
		t.Fatalf("large category used %d bytes", large.bytes)
	}
	small := newAssessmentCapture(context.Background())
	small.budget = budget
	if err := small.add("later category"); err != nil {
		t.Fatalf("reserve not honored after shared budget ran out: %v", err)
	}
	c := newAssessmentCapture(context.Background())
	c.failure(basedata.CollectionResult{Status: basedata.CollectionAccessDenied})
	c.failure(basedata.CollectionResult{Status: basedata.CollectionFailed, ErrorCode: "collection_limit"})
	if !c.data.Truncated || c.data.Result.Status != basedata.CollectionAccessDenied {
		t.Fatal("lost partial failure or truncation")
	}
}

func FuzzTaskPayloadProjection(f *testing.F) {
	f.Add(`<Task><Actions><Exec><Command>C:\job.ps1</Command></Exec></Actions></Task>`)
	f.Fuzz(func(t *testing.T, raw string) { _, _ = parseTaskPayloads(raw) })
}

func FuzzEventMetadataProjection(f *testing.F) {
	f.Add(`<Event><System><EventID>10004</EventID></System></Event>`)
	f.Fuzz(func(t *testing.T, raw string) { _, _ = projectAssessmentEvent(raw, true) })
}
