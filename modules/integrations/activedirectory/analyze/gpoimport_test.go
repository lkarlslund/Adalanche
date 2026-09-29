package analyze

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func TestGPOCredentialImportDoesNotLogContents(t *testing.T) {
	const secret = "synthetic-secret-marker"
	const account = "synthetic-account-marker"
	oldLevel := ui.GetLoglevel()
	ui.SetLoglevel(ui.LevelDebug)
	logPath := filepath.Join(t.TempDir(), "import.log")
	if err := ui.SetLogFile(logPath, ui.LevelDebug); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ui.SetLoglevel(oldLevel)
		if err := ui.SetLogFile("", oldLevel); err != nil {
			t.Error(err)
		}
	})
	for _, tt := range []struct {
		name, contents string
		wantError      bool
	}{
		{"password first", `<Properties cpassword="` + secret + `" userName="` + account + `" />`, false},
		{"username first", `<Properties userName="` + account + `" cpassword="` + secret + `" />`, false},
		{"unrecognized entry", `<Properties cpassword="` + secret + `" account="` + account + `" />`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			graph := newADTestGraph()
			err := ImportGPOInfo(activedirectory.GPOdump{GPOinfo: activedirectory.GPOinfo{
				GUID:  uuid.Must(uuid.FromString("5396e64f-29c8-46b9-a757-984c9504ebbd")),
				Path:  "/synthetic/policy",
				Files: []activedirectory.GPOfileinfo{{RelativePath: "/credentials.xml", Contents: []byte(tt.contents)}},
			}}, graph)
			if (err != nil) != tt.wantError {
				t.Fatalf("import error = %v, want error %v", err, tt.wantError)
			}
			if err != nil && (strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), account)) {
				t.Fatal("import error contains credential data")
			}
			if !tt.wantError {
				// Evidence remains in the graph; only diagnostic disclosure is removed.
				evidence, found := graph.Find(ExposedPassword, engine.NV(secret))
				if !found {
					t.Fatal("credential evidence was not retained")
				}
				target, found := graph.Find(engine.SAMAccountName, engine.NV(account))
				if !found {
					t.Fatal("credential target was not retained")
				}
				requireEdgeSet(t, graph, evidence, target, EdgeExposesPassword)
			}
		})
	}
	taskXML := `<ScheduledTasks><TaskV2><Properties><Task><Principals><Principal><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions><Exec><Command>\\synthetic\share\` + secret + `.exe</Command></Exec></Actions></Task></Properties></TaskV2></ScheduledTasks>`
	if tasks := GPOparseScheduledTasks(taskXML); len(tasks) != 1 {
		t.Fatalf("scheduled-task fixture produced %d tasks, want 1", len(tasks))
	}
	if err := ImportGPOInfo(activedirectory.GPOdump{GPOinfo: activedirectory.GPOinfo{
		Path:  "/synthetic/tasks",
		Files: []activedirectory.GPOfileinfo{{RelativePath: "/machine/preferences/scheduledtasks/scheduledtasks.xml", Contents: []byte(taskXML)}},
	}}, newADTestGraph()); err != nil {
		t.Fatal(err)
	}
	logs, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logs), secret) || strings.Contains(string(logs), account) || strings.Contains(string(logs), "<Properties") {
		t.Fatal("diagnostic log contains credential data or raw file contents")
	}
}
