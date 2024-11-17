package aql

import (
	"github.com/gin-gonic/gin"
	"github.com/lkarlslund/adalanche/modules/engine"
)

// Can return built in queries and user defined persisted queries
type QueryDefinition struct {
	Name    string `json:"name"`
	Default bool   `json:"default,omitempty"`
	Query   string `json:"query,omitempty"`

	MaxDepth                  int                `json:"max_depth,omitempty,string"`
	MaxOutgoingConnections    int                `json:"max_outgoing_connections,omitempty,string"`
	MinAccumulatedProbability engine.Probability `json:"min_accumulated_probability,omitempty,string"`

	UserDefined bool `json:"user_defined,omitempty"`
}

func DefaultQueryDefinition() QueryDefinition {
	return QueryDefinition{
		Name:                   "Untitled Query",
		Query:                  "(&(objectClass=group)(|(name=Domain Admins)(name=Enterprise Admins)))<-[*1..10]-(type=Person)",
		MaxDepth:               -1,
		MaxOutgoingConnections: -1,
	}
}

func (q QueryDefinition) ID() string {
	return q.Name
}

// Compiles the query and makes it a resolver
func (qd QueryDefinition) Resolver(ao *engine.Objects) (AQLresolver, error) {
	return ParseAQLQuery(qd.Query, ao)
}

var (
	DefaultQuerySettings = QueryDefinition{
		MaxDepth: 99,
	}
)

func ParseQueryDefinitionFromPOST(ctx *gin.Context) (QueryDefinition, error) {
	qd := DefaultQueryDefinition()

	err := ctx.ShouldBindBodyWithJSON(&qd)
	if err != nil {
		return qd, err
	}

	return qd, nil
}

func ParseObjectTypeStrings(typeslice []string) (map[engine.ObjectType]struct{}, error) {
	result := make(map[engine.ObjectType]struct{})
	for _, t := range typeslice {
		ot, found := engine.ObjectTypeLookup(t)
		if found {
			result[ot] = struct{}{}
		}
	}
	return result, nil
}
