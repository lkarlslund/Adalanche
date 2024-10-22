package analyze

import (
	"github.com/gin-gonic/gin"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/query"
)

// Can return built in queries and user defined persisted queries
type QueryDefinition struct {
	Name              string   `json:"name"`
	Default           bool     `json:"default,omitempty"`
	QueryFirst        string   `json:"query_first,omitempty"`
	QueryMiddle       string   `json:"query_middle,omitempty"`
	QueryLast         string   `json:"query_last,omitempty"`
	ObjectTypesFirst  []string `json:"object_types_first,omitempty"`
	ObjectTypesMiddle []string `json:"object_types_middle,omitempty"`
	ObjectTypesLast   []string `json:"object_types_last,omitempty"`
	EdgesFirst        []string `json:"edges_first,omitempty"`
	EdgesMiddle       []string `json:"edges_middle,omitempty"`
	EdgesLast         []string `json:"edges_last,omitempty"`

	MaxDepth               int `json:"max_depth,omitempty,string"`
	MaxOutgoingConnections int `json:"max_outgoing_connections,omitempty,string"`

	Direction engine.EdgeDirection `json:"direction"`
	Backlinks int                  `json:"backlinks,omitempty,string"`

	MinEdgeProbability        engine.Probability `json:"min_edge_probability,omitempty,string"`
	MinAccumulatedProbability engine.Probability `json:"min_accumulated_probability,omitempty,string"`
	PruneIslands              bool               `json:"prune_islands,omitempty"`
	DontExpandAUEO            bool               `json:"dont_expand_aueo,omitempty"`

	UserDefined bool `json:"user_defined,omitempty"`
}

func DefaultQueryDefinition() QueryDefinition {
	return QueryDefinition{
		QueryFirst:             "(&(objectClass=group)(|(name=Domain Admins)(name=Enterprise Admins)))",
		MaxDepth:               -1,
		MaxOutgoingConnections: -1,
	}
}

func (q QueryDefinition) ID() string {
	return q.Name
}

func (qd QueryDefinition) AnalysisOptions(ao *engine.Objects) (AnalyzeOptions, error) {
	aoo := NewAnalyzeObjectsOptions()

	filter, err := query.ParseLDAPQueryStrict(qd.QueryFirst, ao)
	if err != nil {
		return aoo, err
	}
	aoo.FilterFirst = filter

	if qd.QueryMiddle != "" {
		filter, err = query.ParseLDAPQueryStrict(qd.QueryMiddle, ao)
		if err != nil {
			return aoo, err
		}
		aoo.FilterMiddle = filter
	}

	if qd.QueryLast != "" {
		filter, err = query.ParseLDAPQueryStrict(qd.QueryLast, ao)
		if err != nil {
			return aoo, err
		}
		aoo.FilterLast = filter
	}

	// ObjectTypes

	aoo.ObjectTypesFirst = make(map[engine.ObjectType]struct{})
	if len(qd.ObjectTypesFirst) == 0 {
		for i, ot := range engine.ObjectTypes() {
			if ot.DefaultEnabledF {
				aoo.ObjectTypesFirst[engine.ObjectType(i)] = struct{}{}
			}
		}
	} else {
		for _, otname := range qd.ObjectTypesFirst {
			ot, found := engine.ObjectTypeLookup(otname)
			if found {
				aoo.ObjectTypesFirst[ot] = struct{}{}
			}
		}
	}

	aoo.ObjectTypesMiddle = make(map[engine.ObjectType]struct{})
	if len(qd.ObjectTypesMiddle) == 0 {
		for i, ot := range engine.ObjectTypes() {
			if ot.DefaultEnabledM {
				aoo.ObjectTypesMiddle[engine.ObjectType(i)] = struct{}{}
			}
		}
	} else {
		for _, otname := range qd.ObjectTypesMiddle {
			ot, found := engine.ObjectTypeLookup(otname)
			if found {
				aoo.ObjectTypesMiddle[ot] = struct{}{}
			}
		}
	}

	aoo.ObjectTypesLast = make(map[engine.ObjectType]struct{})
	if len(qd.ObjectTypesLast) == 0 {
		for i, ot := range engine.ObjectTypes() {
			if ot.DefaultEnabledL {
				aoo.ObjectTypesLast[engine.ObjectType(i)] = struct{}{}
			}
		}
	} else {
		for _, otname := range qd.ObjectTypesLast {
			ot, found := engine.ObjectTypeLookup(otname)
			if found {
				aoo.ObjectTypesLast[ot] = struct{}{}
			}
		}
	}

	// Edgetypes

	if len(qd.EdgesFirst) > 0 {
		aoo.EdgesFirst, err = engine.EdgeBitmapFromStringSlice(qd.EdgesFirst)
		if err != nil {
			return aoo, err
		}
	}
	if len(qd.EdgesMiddle) > 0 {
		aoo.EdgesMiddle, err = engine.EdgeBitmapFromStringSlice(qd.EdgesMiddle)
		if err != nil {
			return aoo, err
		}
	}
	if len(qd.EdgesLast) > 0 {
		aoo.EdgesLast, err = engine.EdgeBitmapFromStringSlice(qd.EdgesLast)
		if err != nil {
			return aoo, err
		}
	}
	aoo.MaxDepth = qd.MaxDepth
	aoo.MaxOutgoingConnections = qd.MaxOutgoingConnections
	aoo.Direction = qd.Direction
	aoo.Backlinks = qd.Backlinks
	aoo.MinEdgeProbability = qd.MinEdgeProbability
	aoo.MinAccumulatedProbability = qd.MinAccumulatedProbability
	aoo.PruneIslands = qd.PruneIslands
	// aoo.NodeLimit: qd.NodeLimit,
	aoo.DontExpandAUEO = qd.DontExpandAUEO
	return aoo, nil
}

var (
	DefaultQuerySettings = QueryDefinition{
		MaxDepth: 99,
	}

	PredefinedQueries = []QueryDefinition{
		{
			Name:       "Who owns your AD? (Reach Domain Admin etc)",
			QueryFirst: "(&(dataLoader=Active Directory)(type=Group)(|(objectSid=S-1-5-32-544)(objectSid=S-1-5-21-*-512)(objectSid=S-1-5-21-*-519)))",
			Direction:  engine.In,
			Default:    true,
		},
		{
			Name:       "Who can DCsync?",
			QueryFirst: "(&(name=DCsync)(type=Callable-Service-Point))",
			Direction:  engine.In,
		},
		{
			Name:       "How to reach machines that have computer accounts with unconstrained delegation (non-DCs)",
			QueryFirst: "(tag=unconstrained)",
			Direction:  engine.In,
			MaxDepth:   1,
		},
		{
			Name:       "What can accounts with no Kerberos preauth requirement reach? (ASREPROAST)",
			QueryFirst: "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(tag=account_active))",
			Direction:  engine.Out,
			MaxDepth:   1,
		},
		{
			Name:       "Who can pwn your AD by sideloading a custom DLL on your DC? (Old DCs only)",
			QueryFirst: "(distinguishedname=CN=MicrosoftDNS,CN=System,DC=*)",
			Direction:  engine.In,
		},
		{
			Name:       "Who can dump SAM/SYSTEM or your ntds.dit remotely or via RDP? (Server and Backup Operators)",
			QueryFirst: "(&(dataLoader=Active Directory)(|(objectSid=S-1-5-32-551)(objectSid=S-1-5-32-549)))",
			Direction:  engine.In,
		},
		{
			Name:       "Enroll in ESC1 vulnerable certificate templates (client auth + pose as anyone)",
			QueryFirst: "(&(type=PKI-Certificate-Template)(msPKI-Certificate-Name-Flag:and:=1)(|(pKIExtendedKeyUsage=1.3.6.1.5.5.7.3.2)(pKIExtendedKeyUsage=1.3.5.1.5.2.3.4)(pKIExtendedKeyUsage=1.3.6.1.4.1.311.20.2.2)(pKIExtendedKeyUsage=2.5.29.37.0)(pKIExtendedKeyUsage:count:=0)))",
			EdgesFirst: []string{"CertificateEnroll"},
			Direction:  engine.In,
		},
		{
			Name:       "Enroll in ESC15 vulnerable certificate templates (v1 + pose as anyone)",
			QueryFirst: "(&(type=PKI-Certificate-Template)(msPKI-Certificate-Name-Flag:and:=1)(msPKI-Template-Schema-Version=1))",
			EdgesFirst: []string{"CertificateEnroll"},
			Direction:  engine.In,
		},
		{
			Name:       "What can Domain Users, Authenticated Users and Everyone do?",
			QueryFirst: "(&(dataLoader=Active Directory)(|(objectSid=S-1-5-21-*-513)(objectSid=S-1-5-11)(objectSid=S-1-1-0)))",
			Direction:  engine.Out,
		},
		{
			Name:       "Who can dump a virtual DC? (hypervisor/SAN sounding groups)",
			QueryFirst: "(&(dataLoader=Active Directory)(type=Group)(|(name=*vcenter*)(name=*vmware*)(name=*esxi*)(name=*vsan*)(name=*simplivity*)))",
			Direction:  engine.In,
		},
		{
			Name:       "Who can wipe or access your backups? (backup sounding groups)",
			QueryFirst: "(&(dataLoader=Active Directory)(type=Group)(|(name=*backup*)(name=*veeam*)(name=*tsm*)(name=*tivoli storage*)(name=*rubrik*)(name=*commvault*))),(|(objectSid=S-1-5-32-544)(objectSid=S-1-5-21-*-512)(objectSid=S-1-5-21-*-519))",
			Direction:  engine.In,
		},
		{
			Name:       "Who can change GPOs?",
			QueryFirst: "(&(dataLoader=Active Directory)(type=Group-Policy-Container))",
			Direction:  engine.In,
		},
		{
			Name:       "What can users not required to have a password reach?",
			QueryFirst: "(&(dataLoader=Active Directory)(type=Person)(userAccountControl:1.2.840.113556.1.4.803:=32))",
			Direction:  engine.Out,
		},
		{
			Name:       "What can users that can't change password reach?",
			QueryFirst: "(&(type=Person)(userAccountControl:1.2.840.113556.1.4.803:=64))",
			Direction:  engine.Out,
		},
		{
			Name:       "What can users with never expiring passwords reach?",
			QueryFirst: "(&(type=Person)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
			Direction:  engine.Out,
		},
		{
			Name:       "What can accounts that have a password older than 5 years reach?",
			QueryFirst: "(&(objectClass=Person)(!(pwdLastSet=0))(pwdLastSet:since:<-5Y)(!(userAccountControl:and:=2)))",
			Direction:  engine.Out,
		},
		{
			Name:       "What can accounts that have never set a password reach?",
			QueryFirst: "(&(dataLoader=Active Directory)(objectClass=Person)(pwdLastSet=0)(|(logonCount=0)(!(logonCount=*)))(!(userAccountControl:and:=2)))",
			Direction:  engine.Out,
		},
		{

			Name:       "Who can control Protected Users?",
			QueryFirst: "(&(type=Group)(distinguishedName=CN=Protected Users,*))",
			Direction:  engine.In,
		},
		{
			Name:       "What can kerberoastable user accounts reach?",
			QueryFirst: "(&(type=Person)(servicePrincipalName=*)(tag=account_active))",
			Direction:  engine.Out,
		},
		{
			Name:       "What can large groups (more than 100 members) reach?",
			QueryFirst: "(&(type=Group)(member:count:>100))",
			Direction:  engine.Out,
		},
		{
			Name:       "Who can reach Domain Controllers?",
			QueryFirst: "(&(type=Machine)(out=MachineAccount,(&(type=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))))",
			Direction:  engine.In,
		},
		{
			Name:       "Who can reach Read-Only Domain Controllers? (RODC)",
			QueryFirst: "(&(type=Machine)(out=MachineAccount,(&(type=Computer)(primaryGroupId=521))))",
			Direction:  engine.In,
		},
		{
			Name:       "Who can reach computers with unconstrained delegation (non DCs)?",
			QueryFirst: "(&(type=Computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!userAccountControl:1.2.840.113556.1.4.803:=8192))",
			Direction:  engine.In,
		},
		{
			Name:       "Who can reach computers with constrained delegation (non DCs)?",
			QueryFirst: "(&(objectCategory=computer)(msds-allowedtodelegateto=*)(!userAccountControl:1.2.840.113556.1.4.803:=8192))",
			Direction:  engine.In,
		},
		{
			Name:       "Users that are members of more than 25 groups",
			QueryFirst: "(&(type=Person)(memberOf:count:>10))",
			Direction:  engine.In,
		},
		{
			Name:       "Give me 100 random machines",
			QueryFirst: "(&(type=Machine)(out=MachineAccount,(userAccountControl:1.2.840.113556.1.4.803:=4096))(_limit=100))",
			Direction:  engine.In,
		},
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
