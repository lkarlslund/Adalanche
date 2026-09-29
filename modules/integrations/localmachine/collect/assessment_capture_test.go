package collect

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/basedata"
)

func TestAssessmentCaptureLimitsAndPartialRecords(t *testing.T) {
	c := newAssessmentCapture(context.Background())
	c.limit = 8
	if err := c.add("first"); err != nil {
		t.Fatal(err)
	}
	if err := c.add("second"); !errors.Is(err, errAssessmentLimit) {
		t.Fatalf("limit: %v", err)
	}
	c.failure(basedata.CollectionResult{Status: basedata.CollectionAccessDenied})
	c.failure(basedata.CollectionResult{Status: basedata.CollectionCollected})
	if len(c.data.Records) != 1 || c.data.Result.Status != basedata.CollectionAccessDenied || c.bytes != 7 {
		t.Fatalf("lost partial state: %+v", c)
	}
	c = newAssessmentCapture(context.Background())
	for range 10000 {
		if err := c.add(nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.add(nil); !errors.Is(err, errAssessmentLimit) {
		t.Fatalf("record limit: %v", err)
	}
}

func TestAssessmentCaptureCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := newAssessmentCapture(ctx)
	if err := c.add("unused"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(c.data.Records) != 0 {
		t.Fatal("retained canceled record")
	}
}

func TestStartupExecutableProjection(t *testing.T) {
	for command, want := range map[string]string{
		`"C:\Program Files\Agent\agent.exe" --token=secret`: `C:\Program Files\Agent\agent.exe`,
		`C:\Agent\agent.exe --token=secret`:                 `C:\Agent\agent.exe`,
		`C:\Program Files\Agent\agent.exe --token=secret`:   "",
		`"C:\Agent\agent.exe --token=secret`:                "",
		`%SystemRoot%\system32\agent.exe --password secret`: `%SystemRoot%\system32\agent.exe`,
		`cmd /c anything`: "",
		"":                "",
	} {
		if got := startupExecutable(command); got != want {
			t.Errorf("executable = %q, want %q", got, want)
		}
	}
}

func TestWSManProjectionDoesNotKeepSecrets(t *testing.T) {
	raw := `<PlugInConfiguration Name="endpoint" RunAsUser="service" RunAsPassword="secret-one"><InitializationParameters><Param Name="secret-two" Value="secret-three"/></InitializationParameters><Resources><Resource ResourceUri="urn:test:a"><Security Uri="urn:a" Sddl="D:(A;;GA;;;BA)"/></Resource><Resource ResourceUri="urn:test:b"><Security Uri="urn:b" Sddl="D:(A;;GR;;;SY)"/></Resource></Resources></PlugInConfiguration>`
	r, err := wsmanRecord(raw, "plugin")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-") {
		t.Fatal("persisted unrequested content")
	}
	if _, exists := r["SecurityDescriptorSddl"]; exists {
		t.Fatal("merged unrelated resource ACLs")
	}
	entries := r["Security"].([]map[string]string)
	if len(entries) != 2 || entries[0]["ResourceURI"] != "urn:test:a" || entries[1]["ResourceURI"] != "urn:test:b" {
		t.Fatalf("lost ACL scope: %+v", entries)
	}
	if r["Name"] != "endpoint" || r["RunAsUser"] != "service" {
		t.Fatalf("lost metadata: %+v", r)
	}
}

func TestWSManProjectionBounds(t *testing.T) {
	if _, err := wsmanRecord(strings.Repeat("a", (1<<20)+1), "plugin"); !errors.Is(err, errAssessmentLimit) {
		t.Fatal(err)
	}
	if _, err := wsmanRecord("<broken>", "plugin"); err == nil {
		t.Fatal("accepted incomplete XML")
	}
	r, err := wsmanRecord(`<Listener><Address>*</Address><Port>5985</Port><Enabled>true</Enabled><Secret>not retained</Secret></Listener>`, "listener")
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 3 || r["Port"] != "5985" {
		t.Fatalf("unexpected listener: %+v", r)
	}
}
