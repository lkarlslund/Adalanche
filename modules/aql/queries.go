package aql

import (
	"github.com/gin-gonic/gin"
	"github.com/lkarlslund/adalanche/modules/engine"
)

// Can return built in queries and user defined persisted queries
type QueryDefinition struct {
	Name        string `json:"name"`
	Query       string `json:"query,omitempty"`
	Category    string `json:"category,omitempty"` // Optional category for grouping queries in UI
	Description string `json:"description,omitempty"`

	MaxDepth                  int                `json:"max_depth,omitempty"`
	MaxOutgoingConnections    int                `json:"max_outgoing_connections,omitempty"`
	Default                   bool               `json:"default,omitempty"`
	MinAccumulatedProbability engine.Probability `json:"min_accumulated_probability,omitempty"`

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
func (qd QueryDefinition) Resolver(ao *engine.IndexedGraph) (AQLresolver, error) {
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

func ParseObjectTypeStrings(typeslice []string) (map[engine.NodeType]struct{}, error) {
	result := make(map[engine.NodeType]struct{})
	for _, t := range typeslice {
		ot, found := engine.NodeTypeLookup(t)
		if found {
			result[ot] = struct{}{}
		}
	}
	return result, nil
}
