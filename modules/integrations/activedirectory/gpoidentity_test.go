package activedirectory

import "testing"

func TestGPOIdentityFromEveryForm(t *testing.T) {
	const want = "example.test/{31B2F340-016D-11D2-945F-00C04FB984F9}"
	for _, path := range []string{
		`\\dc01.example.test\SysVol\example.test\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Scripts\scripts.ini`,
		`\\EXAMPLE\sysvol\example.test\policies\{31b2f340-016d-11d2-945f-00c04fb984f9}`,
		`\\example.test\SYSVOL\EXAMPLE.TEST\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\User`,
	} {
		if got := GPOIdentityFromPath(path); got != want {
			t.Errorf("%s: got %q", path, got)
		}
	}
	if got := GPOIdentityFromDN("CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=example,DC=test"); got != want {
		t.Errorf("from DN: got %q", got)
	}
	for _, other := range []string{`C:\Windows\System32\GroupPolicy\Machine`, `\\dfs\share\policies\{x}`, `\\server\sysvol\example.test\Policies\not-a-guid`} {
		if got := GPOIdentityFromPath(other); got != "" {
			t.Errorf("%s: got %q, want none", other, got)
		}
	}
	if got := GPOIdentityFromDN("CN=Someone,CN=Users,DC=example,DC=test"); got != "" {
		t.Errorf("non-GPO DN: got %q", got)
	}
}
