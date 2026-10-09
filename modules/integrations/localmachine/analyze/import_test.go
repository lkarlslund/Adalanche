package analyze

import "testing"

func TestDownLevelLogonNameNeedsBothParts(t *testing.T) {
	for _, tt := range []struct{ domain, account, want string }{
		{"CONTOSO", "alice", `CONTOSO\alice`},
		{"CONTOSO", "", ""},
		{"", "alice", ""},
		{" ", "alice", ""},
		{"CONTOSO", `alice\`, ""},
	} {
		if got := downLevelLogonName(tt.domain, tt.account); got != tt.want {
			t.Errorf("downLevelLogonName(%q, %q) = %q, want %q", tt.domain, tt.account, got, tt.want)
		}
	}
}
