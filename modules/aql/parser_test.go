package aql

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
)

func init() {
	engine.NewAttribute("MockAttribute")
	engine.NewAttribute("msPKI-Template-Schema-Version")
	engine.NewEdge("MemberOf")
	engine.NewEdge("MachineAccount")
	engine.NewEdge("MemberOfIndirect")
}

func TestParseTestAQLQueries(t *testing.T) {
	// this runs on a mixture of luck and talent
	queries := []string{
		`(source:objectClass="*" ORDER BY MockAttribute DESC SKIP 5 LIMIT 100)-[MemberOf,Probability=100]->(target:&(objectSid=S-1-5-21-*-519))`,
		`(objectClass="*")-[MemberOf,MemberOfIndirect,(objectClass=*)]->(type="Person")`,
		`(objectClass="*")-[tag=AD]->(type="Person")`,
		`()-[]->()`,      // any-to-any
		`()-[]{2}->()`,   // any-to-any with depth match 2
		`()-[]{1,3}->()`, // any-to-any with depth limit of 1 to 3
	}
	for _, q := range queries {
		_, err := ParseAQLQuery(q, nil)
		if err != nil {
			t.Error(q, err)
		}
	}
}

func TestParsePredefinedAQLQueries(t *testing.T) {
	// this runs on a mixture of luck and talent
	for _, q := range PredefinedQueries {
		_, err := ParseAQLQuery(q.Query, nil)
		if err != nil {
			t.Error(q.Query, err)
		}
	}
}
