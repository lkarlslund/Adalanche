package collect

import (
	"reflect"
	"testing"
)

func TestServicePathCandidates(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    []string
	}{
		{`"C:\Program Files\app\service.exe" -x`, nil},
		{`C:\app\service.exe -x other.exe`, nil},
		{`C:\Program Files\Common Files\service.exe -x`, []string{`C:\Program.exe`, `C:\Program Files\Common.exe`}},
		{`C:\Program Files\not-an-executable`, nil},
	} {
		if got := servicePathCandidates(tc.command); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: got %v want %v", tc.command, got, tc.want)
		}
	}
}
