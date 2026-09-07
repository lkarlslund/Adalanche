package query

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
)

func TestLDAPGlobCompatibility(t *testing.T) {
	t.Parallel()
	node := engine.NewNode(engine.Name, "Ægir")
	for _, query := range []string{"(name=æ*)", "(name:caseExactMatch:=Æ*)", "(&(name=æ*)(name=*gir))"} {
		filter, err := ParseLDAPQueryStrict(query, nil)
		if err != nil {
			t.Fatalf("parse %q: %v", query, err)
		}
		if !filter.Evaluate(node) {
			t.Errorf("query %q did not match", query)
		}
	}
}
