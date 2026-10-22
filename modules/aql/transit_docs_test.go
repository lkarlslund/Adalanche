package aql_test

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/aql"
	_ "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
)

// The transit constraint and edge subquery examples in docs/aql.md parse.
func TestTransitDocExamplesParse(t *testing.T) {
	for _, q := range []string{
		"start:(name=S)-[via >=1 (type=Group)]{1,8}->end:(type=Person)",
		"start:(name=S)-[via <=1 (type=Group)]{1,8}->end:(type=Person)",
		"start:(name=S)-[avoid (name=DC01)]{1,8}->end:(type=Person)",
		"start:(name=S)-[via >=1 (type=Group), avoid (name=DC01)]{1,8}->end:(type=Person)",
		"start:(name=S)-[via all but 1 (tag=tier0)]{1,8}->end:(type=Person)",
		"start:(name=S)-[MemberOfGroup, through (type=Group)]{1,5}->end:(type=Person)",
		"start:(&(name=DCsync)(type=Callable-Service-Point))<-[avoid (out=ResetPassword>=100,(name=DC01))]{1,8}-end:(|(type=Person)(type=Group))",
		"(out=ResetPassword,(name=DC01))",
		"(out=ResetPassword>=100,(name=DC01))",
		"(in=*>50)",
	} {
		if _, err := aql.ParseAQLQuery(q, nil); err != nil {
			t.Errorf("%v: %v", q, err)
		}
	}
}
