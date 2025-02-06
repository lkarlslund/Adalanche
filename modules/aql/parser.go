package aql

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/gobwas/glob"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/query"
	timespan "github.com/lkarlslund/time-timespan"
)

func ParseAQLQuery(s string, ao *engine.Objects) (AQLresolver, error) {
	ts, err := Parse(s)
	if err != nil {
		return nil, err
	}
	resolver, err := parseAQLstream(ts, ao)
	if err != nil {
		return nil, fmt.Errorf("parsing error: %v around position %v", err, ts.Token().Position.TC)
	}
	return resolver, nil
}

func parseAQLstream(ts *TokenStream, ao *engine.Objects) (AQLresolver, error) {
	var queries []AQLresolver
	r, err := parseAQLquery(ts, ao)
	if err != nil {
		return nil, err
	}
	queries = append(queries, r)
	for !ts.EOF() && ts.Token().Type == Union {
		ts.Next()
		r, err := parseAQLquery(ts, ao)
		if err != nil {
			return nil, err
		}
		queries = append(queries, r)
	}
	if len(queries) == 1 {
		return queries[0], nil
	}
	return AQLqueryUnion{queries: queries}, nil
}

func parseAQLquery(ts *TokenStream, ao *engine.Objects) (AQLresolver, error) {
	result := AQLquery{
		datasource: ao,
		Mode:       Acyclic, // default to something sane
	}

	for ts.Token().Is(Identifier) && ts.PeekNextRawToken().Is(Whitespace) {
		switch strings.ToUpper(ts.Token().Value) {
		case "WALK":
			result.Mode = Walk // Say goodbye to your CPU
		case "TRAIL":
			result.Mode = Trail
		case "ACYCLIC":
			result.Mode = Acyclic
		case "SIMPLE":
			result.Mode = Simple
		// case "SHORTEST":
		// 	result.Shortest = true
		default:
			return nil, fmt.Errorf("Unknown query mode: %v", ts.Token().Value)
		}
		ts.Next()
	}

	// first there must be a wherefilter
	nq, err := parseNodeFilter(ts, ao)
	if err != nil {
		return nil, err
	}
	result.Sources = append(result.Sources, nq)

	for ts.Token().Type == EdgeAnyDirection || ts.Token().Type == EdgeIn {
		eq, err := parseEdgeQuery(ts, ao)
		if err != nil {
			return result, err
		}

		result.Next = append(result.Next, eq)

		nq, err = parseNodeFilter(ts, ao)
		if err != nil {
			return result, err
		}

		result.Sources = append(result.Sources, nq)
	}

	if !ts.EOF() {
		return nil, fmt.Errorf("Expected end of query but found: %v", ts.Token().Value)
	}
	return result, nil
}

func parseNodeFilter(ts *TokenStream, ao *engine.Objects) (NodeQuery, error) {
	var result NodeQuery

	if ts.Token().Type == Identifier && (ts.PeekNextToken().Type == Colon || ts.PeekNextToken().Type == Is) {
		result.Reference = ts.Token().Value
		ts.Next()
		ts.Next()
	}

	if !ts.NextIfIs(LParan) {
		return NodeQuery{}, errors.New("Expecting ( as start of node query")
	}

	// If RParan there is no selector, just select everything
	if !ts.NextIfIs(RParan) {
		where, err := parseLDAPFilterUnwrapped(ts, ao)
		if err != nil {
			return result, err
		}
		result.Selector = where

		if !ts.NextIfIs(RParan) {
			return NodeQuery{}, errors.New("Expecting ) at end of LDAP filter")
		}

	}

	// If we parse ORDER BY, it's fine
	sorter, err := parseNodeSorter(ts, ao)
	if err != nil {
		return result, err
	}
	result.OrderBy = sorter // might be nil, if there was none

	// If we parse a SKIP, it's fine
	if ts.NextIfIs(Skip) || ts.NextIfIs(Offset) {
		skip := ts.Token()
		if skip.Type != Integer {
			return result, fmt.Errorf("SKIP value expects Integer, but I got %v (%v)", skip.Type, skip.Value)
		}

		result.Skip = int(skip.Native.(int64))
		if result.Skip == 0 {
			return result, fmt.Errorf("SKIP value expects Integer > 0 or Integer < 0, but I got %v", skip.Value)
		}

		ts.Next()
	}

	if ts.NextIfIs(Limit) {
		limit := ts.Token()
		if limit.Type != Integer {
			return result, fmt.Errorf("LIMIT value expects Integer, but I got %v", limit.Type)
		}
		result.Limit = int(limit.Native.(int64))
		if result.Limit == 0 {
			return result, fmt.Errorf("LIMIT value expects Integer > 0 or Integer < 0, but I got %v", limit.Value)
		}

		ts.Next()
	}

	return result, nil
}

func parseNodeSorter(ts *TokenStream, ao *engine.Objects) (NodeSorter, error) {
	if !ts.NextIfIs(OrderBy) {
		return nil, nil
	}

	var result NodeSorterImpl

	// possible alias for results
	if ts.Token().Type != Identifier {
		return nil, fmt.Errorf("ORDER BY should be followed by identifier, we found %v", ts.Token().Value)
	}

	// Store name
	a := engine.LookupAttribute(ts.Token().Value)
	if a == engine.NonExistingAttribute {
		return nil, fmt.Errorf("ORDER BY clause contains non existing attribute %v", ts.Token().Value)
	}
	result.Attr = a
	ts.Next()

	if ts.NextIfIs(Desc) {
		result.Descending = true
	}

	return result, nil
}

func parseLDAPFilter(ts *TokenStream, ao *engine.Objects) (query.NodeFilter, error) {
	if ts.Token().Type != LParan {
		return nil, errors.New("Expecting (")
	}
	ts.Next()
	result, err := parseLDAPFilterUnwrapped(ts, ao)
	if err != nil {
		return nil, err
	}
	if ts.Token().Type != RParan {
		return nil, errors.New("Expecting )")
	}
	ts.Next()
	return result, nil
}

// Parse the LDAP filter without surrounding ()
func parseLDAPFilterUnwrapped(ts *TokenStream, ao *engine.Objects) (query.NodeFilter, error) {
	var subqueries []query.NodeFilter
	var err error

	var invert bool

	if ts.NextIfIs(Not) || ts.NextIfIs(Exclamation) {
		invert = true
	}

	if ts.Token().Type == LParan {
		// Double wrapped!?
		return parseLDAPFilter(ts, ao)
	}

	if ts.Token().Type == BinaryAnd || ts.Token().Type == BinaryOr {
		operator := ts.Token()
		ts.Next()

		// Parse another
		for ts.Token().Type == LParan {
			subquery, err := parseLDAPFilter(ts, ao)
			if err != nil {
				return nil, err
			}
			subqueries = append(subqueries, subquery)
		}
		var result query.NodeFilter
		switch operator.Type {
		case BinaryAnd:
			result = query.AndQuery{subqueries}
		case BinaryOr:
			result = query.OrQuery{subqueries}
		default:
			return nil, fmt.Errorf("Unknown LDAP operator, expected & or |, got %v", operator.Value)
		}
		if invert {
			result = query.NotQuery{result}
		}
		return result, nil
	}

	var result query.NodeFilter

	if result != nil {
		if invert {
			result = query.NotQuery{result}
		}
		return result, nil
	}

	// parse one Attribute = Value pair
	var modifier string
	var attributename, attributename2 string

	// Attribute name
	if ts.Token().Type != Identifier {
		return nil, errors.New("Expected identifier")
	}
	attributename = ts.Token().Value
	ts.Next()

	// Modifier
	if ts.Token().Type == Colon {
		ts.Next()
		modifier += ts.SnarfTextUntil(Colon)
		ts.Next()
	}

	// "function call" modifier
	if ts.Token().Type == LParan {
		ts.Next()
		attributename2 = ts.Token().Value
		ts.Next()
		if ts.Token().Type != RParan {
			return nil, fmt.Errorf("Expected ) we got %v", ts.Token().Value)
		}
		ts.Next()
	}

	// Comparator
	if ts.Token().Type == Tilde {
		if ts.PeekNextToken().Type != Equals {
			return nil, errors.New("Tilde operator MUST be followed by EQUALS")
		}
		// Microsoft LDAP does not distinguish between ~= and =, so we don't care either
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/0bb88bda-ed8d-4af7-9f7b-813291772990
		ts.Next()
	}

	var comparator query.ComparatorType

	switch ts.Token().Type {
	case LessThan:
		comparator = query.CompareLessThan
	case LessThanEquals:
		comparator = query.CompareLessThanEqual
	case GreaterThan:
		comparator = query.CompareGreaterThan
	case GreaterThanEquals:
		comparator = query.CompareGreaterThanEqual
	case Equals:
		comparator = query.CompareEquals
	default:
		return nil, errors.New("Expected comparator, got " + ts.Token().Value)
	}
	ts.Next()

	if len(attributename) == 0 {
		return nil, errors.New("Empty attribute name detected")
	}

	var attributes []engine.Attribute

	if strings.ContainsAny(attributename, "*?") {
		if attributename == "*" {
			// All attributes, don't add anything to the attribute list
		} else {
			gm, err := glob.Compile(attributename)
			if err != nil {
				return nil, fmt.Errorf("Invalid attribute glob match pattern '%v': %s", attributename, err)
			}
			for _, attr := range engine.Attributes() {
				if gm.Match(attr.String()) {
					attributes = append(attributes, attr)
				}
			}
			if len(attributes) == 0 {
				return nil, fmt.Errorf("No attributes matched pattern '%v'", attributename)
			}
		}
	} else {
		// Magic attributes, uuuuuh ....

		switch strings.ToLower(attributename) {
		case "_id":
			value, err := parseValue(ts, ao)
			if err != nil {
				return nil, err
			}
			i, err := strconv.ParseInt(value.String(), 10, 64)
			// i, ok := value.Raw().(int64)
			if err != nil {
				return nil, fmt.Errorf("Could not convert value to integer for id comparison: %v", err)
			}
			return &id{comparator, i}, nil
		case "out", "in":
			edgename := ts.Token().String()
			ts.Next()
			var target query.NodeFilter
			if ts.NextIfIs(Comma) {
				target, err = parseLDAPFilter(ts, ao)
				if err != nil {
					return nil, fmt.Errorf("Could not parse sub-query: %v", err)
				}
			}
			var edge engine.Edge
			if edgename == "*" {
				edge = engine.AnyEdgeType
			} else {
				edge = engine.LookupEdge(edgename)
				if edge == engine.NonExistingEdge {
					return nil, fmt.Errorf("Could not convert value %v to edge", edgename)
				}
			}
			direction := engine.Out
			if strings.EqualFold(attributename, "_pwnable") || strings.EqualFold(attributename, "in") {
				direction = engine.In
			}
			return query.EdgeQuery{
				Direction: direction,
				Edge:      edge,
				Target:    target}, nil
		default:
			attribute := engine.A(attributename)
			if attribute == engine.NonExistingAttribute {
				return nil, fmt.Errorf("Unknown attribute %v", attributename)
			}
			attributes = []engine.Attribute{attribute}
		}
	}

	attribute2 := engine.NonExistingAttribute
	if attributename2 != "" {
		attribute2 = engine.A(attributename2)
		if attribute2 == engine.NonExistingAttribute {
			return nil, fmt.Errorf("Unknown attribute %v", attributename2)
		}
	}

	var casesensitive bool

	var genwrapper func(aq query.FilterAttribute) query.NodeFilter

	switch len(attributes) {
	case 0:
		genwrapper = func(aq query.FilterAttribute) query.NodeFilter {
			return query.FilterAnyAttribute{aq}
		}
	case 1:
		genwrapper = func(aq query.FilterAttribute) query.NodeFilter {
			return query.FilterOneAttribute{Attribute: attributes[0], FilterAttribute: aq}
		}
	default:
		genwrapper = func(aq query.FilterAttribute) query.NodeFilter {
			return query.FilterMultipleAttributes{
				Attributes:          attributes,
				AttributeGlobString: attributename,
				FilterAttribute:     aq}
		}
	}

	// Decide what to do
	switch modifier {
	case "":
		// That's OK, this is default :-) - continue below
	case "caseExactMatch":
		casesensitive = true
	case "count":
		if !ts.Token().Is(Integer) {
			return nil, fmt.Errorf("Modifier count requires an integer, we got %v", ts.Token())
		}

		i := ts.Token().Native.(int64)
		ts.Next()

		result = genwrapper(query.CountModifier{Comparator: comparator, Value: int(i)})
	case "len", "length":
		if !ts.Token().Is(Integer) {
			return nil, fmt.Errorf("Modifier length requires an integer, we got %v", ts.Token())
		}

		i := ts.Token().Native.(int64)
		ts.Next()

		result = genwrapper(query.LengthModifier{Comparator: comparator, Value: int(i)})
	case "since":
		// try to parse it as an duration
		value, err := parseRelaxedValue(ts, ao)
		if err != nil {
			return nil, err
		}

		duration, err := timespan.ParseTimespan(value.String())
		if err != nil {
			return nil, errors.New("Could not parse value as a duration (5h2m)")
		}

		result = genwrapper(query.SinceModifier{
			Comparator: comparator,
			TimeSpan:   duration})
		break
	case "timediff":
		if attribute2 == engine.NonExistingAttribute {
			return nil, errors.New("timediff modifier requires two attributes")
		}

		// try to parse it as an duration
		value, err := parseRelaxedValue(ts, ao)
		if err != nil {
			return nil, err
		}

		// try to parse it as an duration
		duration, err := timespan.ParseTimespan(value.String())
		if err != nil {
			return nil, errors.New("Could not parse value as a duration (5h2m)")
		}
		result = genwrapper(query.TimediffModifier{
			Attribute2: attribute2,
			Comparator: comparator,
			TimeSpan:   duration})
		break
	case "1.2.840.113556.1.4.803", "and":
		if comparator != query.CompareEquals {
			return nil, errors.New("Modifier 1.2.840.113556.1.4.803 requires equality comparator")
		}

		if !ts.Token().Is(Integer) {
			return nil, fmt.Errorf("Modifier 'and' requires an integer, we got %v", ts.Token())
		}

		i := ts.Token().Native.(int64)
		ts.Next()

		result = genwrapper(query.BinaryAndModifier{i})
	case "1.2.840.113556.1.4.804", "or":
		if comparator != query.CompareEquals {
			return nil, errors.New("Modifier 1.2.840.113556.1.4.804 requires equality comparator")
		}
		if !ts.Token().Is(Integer) {
			return nil, fmt.Errorf("Modifier 'or' requires an integer, we got %v", ts.Token())
		}

		i := ts.Token().Native.(int64)
		ts.Next()

		result = genwrapper(query.BinaryOrModifier{i})
	case "1.2.840.113556.1.4.1941", "dnchain":
		// Matching rule in chain
		value, err := parseRelaxedValue(ts, ao)
		if err != nil {
			return nil, err
		}

		result = genwrapper(query.RecursiveDNmatcher{
			DN: value.String(),
			AO: ao})
	default:
		return nil, errors.New("Unknown modifier " + modifier)
	}

	value, err := parseRelaxedValue(ts, ao)
	if err != nil {
		return nil, err
	}

	if result == nil {
		// string comparison
		strval := value.String()
		if comparator == query.CompareEquals {
			if value.String() == "*" {
				result = genwrapper(query.HasAttr{})
			} else if strings.HasPrefix(strval, "/") && strings.HasSuffix(strval, "/") {
				// regexp magic
				pattern := strval[1 : len(strval)-1]
				r, err := regexp.Compile(pattern)
				if err != nil {
					return nil, err
				}
				result = genwrapper(query.HasRegexpMatch{r})
			} else if strings.ContainsAny(strval, "?*") {
				// glob magic
				pattern := strval
				if !casesensitive {
					pattern = strings.ToLower(pattern)
				}
				g, err := glob.Compile(pattern)
				if err != nil {
					return nil, err
				}
				if casesensitive {
					result = genwrapper(query.HasGlobMatch{
						Casesensitive: true,
						Globstr:       pattern,
						Match:         g})
				} else {
					result = genwrapper(query.HasGlobMatch{
						Casesensitive: false,
						Globstr:       pattern,
						Match:         g})
				}
			} else {
				result = genwrapper(query.HasStringMatch{
					Casesensitive: casesensitive,
					Value:         engine.NewAttributeValueString(strval)})
			}
		}
	}

	if result == nil {
		// the other comparators require numeric value
		i, err := strconv.ParseInt(value.String(), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("Could not convert value to integer for numeric comparison: %v", err)
		}
		result = genwrapper(query.TypedComparison[int64]{
			Comparator: comparator,
			Value:      i})
	}

	if invert {
		result = query.NotQuery{result}
	}

	return result, nil
}

// allows unquoted strings as values
func parseRelaxedValue(ts *TokenStream, ao *engine.Objects) (engine.AttributeValue, error) {
	if ts.Token().Is(QuotedString) {
		value := engine.NewAttributeValueString(ts.Token().String())
		ts.Next()
		return value, nil
	}
	return engine.NewAttributeValueString(ts.SnarfTextUntil(RParan)), nil
}

func parseValue(ts *TokenStream, ao *engine.Objects) (engine.AttributeValue, error) {
	var value engine.AttributeValue
	switch ts.Token().Type {
	case Integer:
		value = engine.AttributeValueInt(ts.Token().Native.(int64))
	case Float:
		return nil, errors.New("float type not supported yet")
	case QuotedString:
		value = engine.NewAttributeValueString(ts.Token().Value)
	case True, False:
		value = engine.AttributeValueBool(ts.Token().Type == True) // brilliant++
	default:
		return nil, fmt.Errorf("unexpected value %v (type %v)"+ts.Token().Value, ts.Token().Type.String())
	}

	ts.Next()
	return value, nil
}

func parseIndexLookup(ts *TokenStream, ao *engine.Objects) (IndexLookup, error) {
	var result IndexLookup
	attr, err := parseAttribute(ts, ao)
	if err != nil {
		return result, err
	}
	result.a = attr

	if ts.Token().Type != Colon {
		return result, errors.New("Expecting colon after index lookup attribute")
	}
	ts.Next()

	val, err := parseValue(ts, ao)
	if err != nil {
		return result, err
	}
	result.v = val

	return result, nil
}

func parseAttribute(ts *TokenStream, ao *engine.Objects) (engine.Attribute, error) {
	if ts.Token().Type != Identifier {
		return engine.NonExistingAttribute, errors.New("Expecting index lookup attribute")
	}
	attr := engine.LookupAttribute(ts.Token().Value)
	if attr == engine.NonExistingAttribute {
		return engine.NonExistingAttribute, fmt.Errorf("Unknown attribute %v references in index lookup", ts.Token().Value)
	}
	ts.Next()
	return attr, nil
}

// func parseWhere(ts *TokenStream, ao *engine.Objects) (query.NodeFilter, error) {
// 	if ts.Token().Type != Where {
// 		return nil, errors.New("WHERE expected")
// 	}
// 	ts.Next()

// 	// attribute operator value (ObjectClassSimple == "blabla")
// 	ts.Next()
// 	if ts.Token().Type != Identifier {
// 		return nil, errors.New("Attribute identifier expected in WHERE clause")
// 	}

// 	val, err := parseAttributeValue(ts, ao)
// 	if err != nil {
// 		return result, err
// 	}
// 	result.v = val

// 	ts.Next() // Eat comma, loop

// }

func parseEdgeQuery(ts *TokenStream, ao *engine.Objects) (EdgeSearcher, error) {
	es := EdgeSearcher{
		Direction:     engine.Any,
		MinIterations: 1,
		MaxIterations: 1,
		FilterEdges: EdgeMatcher{
			Comparator: query.CompareGreaterThanEqual,
			Count:      1,
		},
		ProbabilityComparator: query.CompareGreaterThanEqual,
		ProbabilityValue:      1,
	}

	if ts.NextIfIs(EdgeAnyDirection) {
		// do nothing
	} else if ts.NextIfIs(EdgeIn) {
		es.Direction = engine.In
	} else {
		return EdgeSearcher{}, errors.New("Expecting edge indicator at start of edge query")
	}

	if !ts.NextIfIs(LBracket) {
		return EdgeSearcher{}, errors.New("Expecting [ at start of edge query")
	}

	if !ts.NextIfIs(RBracket) {
		first := true
		for {
			if !first {
				// need a seperator
				if !ts.NextIfIs(Comma) {
					return es, errors.New("Expecting comma between edges in edge query")
				}
			} else {
				first = false
			}

			if ts.Token().Is(LParan) {
				if es.PathNodeRequirement != nil {
					return es, errors.New("Only one path node requirement is supported in edge query")
				}
				// Node requirement filter LDAP style
				requirement, err := parseNodeFilter(ts, ao)
				if err != nil {
					return es, fmt.Errorf("Expected node requirement in edge query, but got %v", err)
				}
				es.PathNodeRequirement = &requirement
			} else {
				if ts.Token().Type != Identifier {
					return EdgeSearcher{}, fmt.Errorf("Expecting identifier in edge matcher, but we got %v (%v)", ts.Token().Value, ts.Token().Type)
				}
				if strings.EqualFold(ts.Token().Value, "probability") {
					ts.Next()
					comparator, err := GetComparator(ts)
					if err != nil {
						return es, fmt.Errorf("Expected comparator in edge query, but got %v (%v)", ts.Token().Type, ts.Token().Value)
					}

					if ts.Token().Type != Integer {
						return es, fmt.Errorf("Expected probability in edge query, but got %v (%v)", ts.Token().Type, ts.Token().Value)
					}
					probability := ts.Token().Native.(int64)
					ts.Next()

					es.ProbabilityComparator = comparator
					es.ProbabilityValue = engine.Probability(probability)
				} else if strings.EqualFold(ts.Token().Value, "tag") {
					ts.Next() // eat tag identifier
					comparator, err := GetComparator(ts)
					if err != nil {
						return es, fmt.Errorf("Expected comparator in edge query, but got %v (%v)", ts.Token().Type, ts.Token().Value)
					}
					if comparator != query.CompareEquals {
						return es, fmt.Errorf("Tag requires equals, but we got %v (%v)", comparator, ts.Token().Value)
					}
					if ts.Token().Type != Identifier {
						return es, fmt.Errorf("Expected tag name, but got %v (%v)", ts.Token().Type, ts.Token().Value)
					}
					tagname := ts.Token().Value
					ts.Next()

					// find all the edges with that tag
					for _, edge := range engine.Edges() {
						if edge.HasTag(tagname) {
							es.FilterEdges.Bitmap.Set(edge)
						}
					}
				} else if strings.EqualFold(ts.Token().Value, "match") {
					ts.Next() // eat tag identifier
					comparator, err := GetComparator(ts)
					if err != nil {
						return es, fmt.Errorf("Expected comparator in edge query 'match' restrictions, %v", err)
					}
					if !ts.Token().Is(Integer) {
						return es, fmt.Errorf("Expected integer in edge query 'match' restrictions, but got %v (%v)", ts.Token().Type, ts.Token().Value)
					}
					count := ts.Token().Native.(int64)
					es.FilterEdges.Comparator = comparator
					es.FilterEdges.Count = count
					ts.Next()
				} else {
					// It has to be an attribute
					edge := engine.LookupEdge(ts.Token().Value)
					if edge == engine.NonExistingEdge {
						return es, fmt.Errorf("Unknown edge %v references in edge query", ts.Token().Value)
					}
					es.FilterEdges.Bitmap = es.FilterEdges.Bitmap.Set(edge) // Add it
					ts.Next()
				}
			}
			if ts.NextIfIs(RBracket) {
				break
			}
		}
	}

	if ts.NextIfIs(LBrace) {
		if !ts.Token().Is(Integer) {
			return EdgeSearcher{}, fmt.Errorf("Expected integer in iteration count, but got %v (%v)", ts.Token().Type, ts.Token().Value)
		}
		es.MinIterations = int(ts.Token().Native.(int64))
		es.MaxIterations = es.MinIterations
		ts.Next()

		if ts.NextIfIs(Comma) {
			if !ts.Token().Is(Integer) {
				return EdgeSearcher{}, fmt.Errorf("Expected integer in iteration count, but got %v (%v)", ts.Token().Type, ts.Token().Value)
			}
			es.MaxIterations = int(ts.Token().Native.(int64))
			ts.Next()
		}

		if !ts.NextIfIs(RBrace) {
			return EdgeSearcher{}, errors.New("Expecting } after min/max iterations in edge query")
		}
	}

	// End of edge query, any indicator of direction?
	if ts.NextIfIs(EdgeOut) {
		if es.Direction != engine.Any {
			return EdgeSearcher{}, errors.New("Only one direction indicator allowed in edge query")
		}
		es.Direction = engine.Out
	} else if !ts.NextIfIs(EdgeAnyDirection) {
		return es, errors.New("Expecting edge indicator at end of edge query")
	}

	// Blank to default edges
	if es.FilterEdges.Bitmap.IsBlank() {
		for _, edge := range engine.Edges() {
			if edge.DefaultF() || edge.DefaultM() || edge.DefaultL() { // Add it
				es.FilterEdges.Bitmap = es.FilterEdges.Bitmap.Set(edge)
			}
		}
	}

	return es, nil
}

func GetComparator(ts *TokenStream) (query.ComparatorType, error) {
	var result query.ComparatorType
	switch ts.Token().Type {
	case Equals:
		result = query.CompareEquals
	case GreaterThan:
		result = query.CompareGreaterThan
	case GreaterThanEquals:
		result = query.CompareGreaterThanEqual
	case LessThan:
		result = query.CompareLessThan
	case LessThanEquals:
		result = query.CompareLessThanEqual
	default:
		return result, errors.New("Unknown comparator")
	}
	ts.Next()
	return result, nil
}
