package collect

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/lkarlslund/adalanche/modules/basedata"
)

func TestCollectBuildNumber(t *testing.T) {
	for _, tt := range []struct {
		name                        string
		build                       any
		buildErr                    error
		revision                    uint32
		revisionErr                 error
		want                        string
		buildStatus, revisionStatus basedata.CollectionStatus
	}{
		{"complete", "26000", nil, 1234, nil, "26000.1234", basedata.CollectionCollected, basedata.CollectionCollected},
		{"zero revision", "26000", nil, 0, nil, "26000.0", basedata.CollectionCollected, basedata.CollectionCollected},
		{"revision missing", "26000", nil, 0, fs.ErrNotExist, "26000", basedata.CollectionCollected, basedata.CollectionNotFound},
		{"revision denied", "26000", nil, 0, fs.ErrPermission, "26000", basedata.CollectionCollected, basedata.CollectionAccessDenied},
		{"revision wrong type", "26000", nil, 0, errors.ErrUnsupported, "26000", basedata.CollectionCollected, basedata.CollectionUnsupported},
		{"revision failed", "26000", nil, 0, errors.New("failed"), "26000", basedata.CollectionCollected, basedata.CollectionFailed},
		{"build missing", "", fs.ErrNotExist, 1234, nil, "", basedata.CollectionNotFound, basedata.CollectionCollected},
		{"key denied", "", fs.ErrPermission, 0, fs.ErrPermission, "", basedata.CollectionAccessDenied, basedata.CollectionAccessDenied},
		{"empty build", "", nil, 1234, nil, "", basedata.CollectionUnsupported, basedata.CollectionCollected},
		{"invalid build", "26000.1234", nil, 1234, nil, "", basedata.CollectionUnsupported, basedata.CollectionCollected},
		{"wrong build type", uint64(26000), nil, 1234, nil, "", basedata.CollectionUnsupported, basedata.CollectionCollected},
	} {
		t.Run(tt.name, func(t *testing.T) {
			outcomes := make(basedata.CollectionResults)
			buildReads, revisionReads := 0, 0
			got := collectBuildNumber(func(path string) (any, error) {
				if path != currentVersionPath+`\CurrentBuildNumber` {
					t.Fatalf("unexpected string read: %s", path)
				}
				buildReads++
				return tt.build, tt.buildErr
			}, func(path string) (uint32, error) {
				if path != currentVersionPath+`\UBR` {
					t.Fatalf("unexpected DWORD read: %s", path)
				}
				revisionReads++
				return tt.revision, tt.revisionErr
			}, outcomes)
			if got != tt.want {
				t.Errorf("build = %q, want %q", got, tt.want)
			}
			if buildReads != 1 || revisionReads != 1 {
				t.Fatalf("reads = %d, %d", buildReads, revisionReads)
			}
			if got := outcomes["registry/value/"+currentVersionPath+`\CurrentBuildNumber`].Status; got != tt.buildStatus {
				t.Errorf("build status = %s, want %s", got, tt.buildStatus)
			}
			if got := outcomes["registry/value/"+currentVersionPath+`\UBR`].Status; got != tt.revisionStatus {
				t.Errorf("revision status = %s, want %s", got, tt.revisionStatus)
			}
		})
	}
}
