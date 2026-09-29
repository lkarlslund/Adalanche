package collect

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/collection"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
)

func TestPolicyStreamDoesNotFollowLinks(t *testing.T) {
	root, outside, output := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "private"), []byte("must-not-collect"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "private"), filepath.Join(root, "link")); err != nil {
		t.Skip("symlinks unavailable")
	}
	path := filepath.Join(output, "policy.gpc")
	if err := writePolicyFiles(context.Background(), path, activedirectory.GPOdump{}, root); err != nil {
		t.Fatal(err)
	}
	info, err := activedirectory.ReadGPOCollection(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range info.Files {
		if len(file.Contents) != 0 {
			t.Fatal("followed content symlink")
		}
		if filepath.Base(file.RelativePath) == "link" && file.CollectionResults["contents"].Status != basedata.CollectionUnsupported {
			t.Fatal("missing unsupported status")
		}
	}
	verified, err := collection.VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Completion.Outcome != collection.Partial {
		t.Fatal("unsupported content reported complete")
	}
}

func TestPolicyStreamMissingRootRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.gpc")
	if err := writePolicyFiles(context.Background(), path, activedirectory.GPOdump{}, filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatal(err)
	}
	info, err := activedirectory.ReadGPOCollection(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.CollectionResults["enumeration"].Status != basedata.CollectionNotFound {
		t.Fatal("missing policy reported collected")
	}
}
