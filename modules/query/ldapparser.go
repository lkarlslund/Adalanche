package query

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/gobwas/glob"
	"github.com/gobwas/glob/util/runes"
	"github.com/lkarlslund/adalanche/modules/engine"
	timespan "github.com/lkarlslund/time-timespan"
)

func ParseLDAPQueryStrict(s string, ao *engine.Objects) (NodeFilter, error) {
	s, query, err := ParseLDAPQuery(s, ao)
	if err == nil && s != "" {
		return nil, fmt.Errorf("Extra data after query parsing: %v", s)
	}
	return query, err
}

func ParseLDAPQuery(s string, ao *engine.Objects) (string, NodeFilter, error) {
	qs, q, err := parseLDAPRuneQuery([]rune(s), ao)
	return string(qs), q, err
}

func parseLDAPRuneQuery(s []rune, ao *engine.Objects) ([]rune, NodeFilter, error) {
	if len(s) < 5 {
		return nil, nil, errors.New("Query string too short")
	}
	if !runes.HasPrefix(s, []rune("(")) || !runes.HasSuffix(s, []rune(")")) {
		return nil, nil, errors.New("Query must start with ( and end with )")
	}
	// Strip (
	s = s[1:]
	var subqueries []NodeFilter
	var err error

	var invert bool

	if s[0] == '!' {
		invert = true
		s = s[1:]
	}

	var result NodeFilter

	switch s[0] {
	case '(': // double wrapped query?
		s, result, err = parseLDAPRuneQuery(s, ao)
		if err != nil {
			return nil, nil, err
		}
		if len(s) == 0 {
			return nil, nil, errors.New("Missing closing ) in query")
		}
		// Strip )
		s = s[1:]
	case '&':
		s, subqueries, err = parseMultipleLDAPRuneQueries(s[1:], ao)
		if err != nil {
			return nil, nil, err
		}
		// Strip )
		s = s[1:]
		result = AndQuery{subqueries}
	case '|':
		s, subqueries, err = parseMultipleLDAPRuneQueries(s[1:], ao)
		if err != nil {
			return nil, nil, err
		}
		if len(s) == 0 {
			return nil, nil, errors.New("Query should end with )")
		}
		// Strip )
		s = s[1:]
		result = OrQuery{subqueries}
	}

	if result != nil {
		if invert {
			result = NotQuery{result}
		}
		return s, result, nil
	}

	// parse one Attribute = Value pair
	var modifier string
	var attributename, attributename2 string

	// Attribute name
attributeloop:
	for {
		if len(s) == 0 {
			return nil, nil, errors.New("Incompete query attribute name detected")
		}
		switch s[0] {
		case '\\': // Escaping
			attributename += string(s[1])
			s = s[2:] // yum yum
		case ':':
			// Modifier
			nextcolon := runes.Index(s[1:], []rune(":"))
			if nextcolon == -1 {
				return nil, nil, errors.New("Incomplete query string detected (only one colon modifier)")
			}
			modifier = string(s[1 : nextcolon+1])
			s = s[nextcolon+2:]

			// "function call" modifier
			if strings.Contains(modifier, "(") && strings.HasSuffix(modifier, ")") {
				paran := strings.Index(modifier, "(")
				attributename2 = string(modifier[paran+1 : len(modifier)-1])
				modifier = string(modifier[:paran])
			}

			break attributeloop
		case ')':
			return nil, nil, errors.New("Unexpected closing parantesis")
		case '~', '=', '<', '>':
			break attributeloop
		default:
			attributename += string(s[0])
			s = s[1:]
		}
	}

	// Comparator
	comparatorstring := string(s[0])
	if s[0] == '~' {
		if s[1] != '=' {
			return nil, nil, errors.New("Tilde operator MUST be followed by EQUALS")
		}
		// Microsoft LDAP does not distinguish between ~= and =, so we don't care either
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/0bb88bda-ed8d-4af7-9f7b-813291772990
		comparatorstring = "="
		s = s[2:]
	} else if (s[0] == '<' || s[0] == '>') && (s[1] == '=') {
		comparatorstring += "="
		s = s[2:]
	} else {
		s = s[1:]
	}

	comparator := CompareEquals
	switch comparatorstring {
	case "<":
		comparator = CompareLessThan
	case "<=":
		comparator = CompareLessThanEqual
	case ">":
		comparator = CompareGreaterThan
	case ">=":
		comparator = CompareGreaterThanEqual
	}

	// Value
	var value string
	var rightparanthesisneeded int
valueloop:
	for {
		if len(s) == 0 {
			return nil, nil, errors.New("Incomplete query value detected")
		}
		switch s[0] {
		case '\\': // Escaping
			value += string(s[1])
			s = s[2:] // yum yum
		case '(':
			rightparanthesisneeded++
			value += string(s[0])
			s = s[1:]
		case ')':
			if rightparanthesisneeded == 0 {
				break valueloop
			}
			value += string(s[0])
			s = s[1:]
			rightparanthesisneeded--
		default:
			value += string(s[0])
			s = s[1:]
		}
	}

	// Eat the )
	s = s[1:]

	valuenum, numok := strconv.ParseInt(value, 10, 64)

	if len(attributename) == 0 {
		return nil, nil, errors.New("Empty attribute name detected")
	}

	var attributes []engine.Attribute

	if strings.ContainsAny(attributename, "*?") {
		if attributename == "*" {
			// All attributes, don't add anything to the attribute list
		} else {
			gm, err := glob.Compile(attributename)
			if err != nil {
				return nil, nil, fmt.Errorf("Invalid attribute glob match pattern '%v': %s", attributename, err)
			}
			for _, attr := range engine.Attributes() {
				if gm.Match(attr.String()) {
					attributes = append(attributes, attr)
				}
			}
			if len(attributes) == 0 {
				return nil, nil, fmt.Errorf("No attributes matched pattern '%v'", attributename)
			}
		}
	} else {
		// Magic attributes, uuuuuh ....
		switch strings.ToLower(attributename) {
		case "_id":
			if numok != nil {
				return nil, nil, errors.New("Could not convert value to integer for id comparison")
			}
			return s, &id{comparator, valuenum}, nil
		case "_limit":
			if numok != nil {
				return nil, nil, errors.New("Could not convert value to integer for limit limiter")
			}
			return s, &Limit{valuenum}, nil
		case "_random100":
			if numok != nil {
				return nil, nil, errors.New("Could not convert value to integer for random100 limiter")
			}
			return s, &Random100{comparator, valuenum}, nil
		case "_pwnable", "_canpwn", "out", "in":
			edgename := value
			var target NodeFilter
			commapos := strings.Index(edgename, ",")
			if commapos != -1 {
				edgename = value[:commapos]
				target, err = ParseLDAPQueryStrict(value[commapos+1:], ao)
				if err != nil {
					return nil, nil, fmt.Errorf("Could not parse sub-query: %v", err)
				}
			}
			var edge engine.Edge
			if edgename == "*" {
				edge = engine.AnyEdgeType
			} else {
				edge = engine.LookupEdge(edgename)
				if edge == engine.NonExistingEdge {
					return nil, nil, fmt.Errorf("Could not convert value %v to edge", edgename)
				}
			}
			direction := engine.Out
			if strings.EqualFold(attributename, "_pwnable") || strings.EqualFold(attributename, "in") {
				direction = engine.In
			}
			return s, EdgeQuery{
				Direction: direction,
				Edge:      edge,
				Target:    target}, nil
		default:
			attribute := engine.A(attributename)
			if attribute == engine.NonExistingAttribute {
				return nil, nil, fmt.Errorf("Unknown attribute %v", attributename)
			}
			attributes = []engine.Attribute{attribute}
		}
	}

	attribute2 := engine.NonExistingAttribute
	if attributename2 != "" {
		attribute2 = engine.A(attributename2)
		if attribute2 == engine.NonExistingAttribute {
			return nil, nil, fmt.Errorf("Unknown attribute %v", attributename2)
		}
	}

	var casesensitive bool

	var genwrapper func(aq FilterAttribute) NodeFilter

	switch len(attributes) {
	case 0:
		genwrapper = func(aq FilterAttribute) NodeFilter {
			return FilterAnyAttribute{aq}
		}
	case 1:
		genwrapper = func(aq FilterAttribute) NodeFilter {
			return FilterOneAttribute{
				Attribute:       attributes[0],
				FilterAttribute: aq}
		}
	default:
		genwrapper = func(aq FilterAttribute) NodeFilter {
			return FilterMultipleAttributes{
				AttributeGlobString: attributename,
				Attributes:          attributes,
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
		if numok != nil {
			return nil, nil, errors.New("Could not convert value to integer for modifier comparison")
		}
		result = genwrapper(CountModifier{comparator, int(valuenum)})
	case "len", "length":
		if numok != nil {
			return nil, nil, errors.New("Could not convert value to integer for modifier comparison")
		}
		result = genwrapper(LengthModifier{comparator, int(valuenum)})
	case "since":
		if numok != nil {
			// try to parse it as an duration
			duration, err := timespan.ParseTimespan(value)
			if err != nil {
				return nil, nil, errors.New("Could not parse value as a duration (5h2m)")
			}
			result = genwrapper(SinceModifier{
				Comparator: comparator,
				TimeSpan:   duration})
			break
		}
		duration, err := timespan.ParseTimespan(fmt.Sprintf("%vs", valuenum))
		if err != nil {
			return nil, nil, errors.New("Could not parse value as a duration of seconds (5h2m)")
		}
		result = genwrapper(SinceModifier{
			Comparator: comparator,
			TimeSpan:   duration})
	case "timediff":
		if attribute2 == engine.NonExistingAttribute {
			return nil, nil, errors.New("timediff modifier requires two attributes")
		}
		if numok != nil {
			// try to parse it as an duration
			duration, err := timespan.ParseTimespan(value)
			if err != nil {
				return nil, nil, errors.New("Could not parse value as a duration (5h2m)")
			}
			result = genwrapper(TimediffModifier{
				Attribute2: attribute2,
				Comparator: comparator,
				TimeSpan:   duration})
			break
		}
		duration, err := timespan.ParseTimespan(fmt.Sprintf("%vs", valuenum))
		if err != nil {
			return nil, nil, errors.New("Could not parse value as a duration of seconds (5h2m)")
		}
		result = genwrapper(TimediffModifier{
			Attribute2: attribute2,
			Comparator: comparator,
			TimeSpan:   duration})
	case "1.2.840.113556.1.4.803", "and":
		if comparator != CompareEquals {
			return nil, nil, errors.New("Modifier 1.2.840.113556.1.4.803 requires equality comparator")
		}
		result = genwrapper(BinaryAndModifier{valuenum})
	case "1.2.840.113556.1.4.804", "or":
		if comparator != CompareEquals {
			return nil, nil, errors.New("Modifier 1.2.840.113556.1.4.804 requires equality comparator")
		}
		result = genwrapper(BinaryOrModifier{valuenum})
	case "1.2.840.113556.1.4.1941", "dnchain":
		// Matching rule in chain
		result = genwrapper(RecursiveDNmatcher{DN: value, AO: ao})
	default:
		return nil, nil, errors.New("Unknown modifier " + modifier)
	}

	if result == nil {
		// string comparison
		if comparator == CompareEquals {
			if value == "*" {
				result = genwrapper(HasAttr{})
			} else if strings.HasPrefix(value, "/") && strings.HasSuffix(value, "/") {
				// regexp magic
				pattern := value[1 : len(value)-1]
				r, err := regexp.Compile(pattern)
				if err != nil {
					return nil, nil, err
				}
				result = genwrapper(HasRegexpMatch{r})
			} else if strings.ContainsAny(value, "?*") {
				// glob magic
				pattern := value
				if !casesensitive {
					pattern = strings.ToLower(pattern)
				}
				g, err := glob.Compile(pattern)
				if err != nil {
					return nil, nil, err
				}
				if casesensitive {
					result = genwrapper(HasGlobMatch{
						Casesensitive: true,
						Globstr:       pattern,
						Match:         g})
				} else {
					result = genwrapper(HasGlobMatch{
						Casesensitive: false,
						Globstr:       pattern,
						Match:         g})
				}
			} else {
				result = genwrapper(HasStringMatch{
					Casesensitive: casesensitive,
					Value:         engine.NewAttributeValueString(value)})
			}
		}
	}

	if result == nil {
		// the other comparators require numeric value
		if numok != nil {
			return nil, nil, fmt.Errorf("Could not convert value %v to integer for numeric comparison", value)
		}
		result = genwrapper(TypedComparison[int64]{
			Comparator: comparator,
			Value:      valuenum})
	}

	if invert {
		result = NotQuery{result}
	}

	return s, result, nil
}

func parseMultipleLDAPRuneQueries(s []rune, ao *engine.Objects) ([]rune, []NodeFilter, error) {
	var result []NodeFilter
	for len(s) > 0 && s[0] == '(' {
		var query NodeFilter
		var err error
		s, query, err = parseLDAPRuneQuery(s, ao)
		if err != nil {
			return s, nil, err
		}
		result = append(result, query)
	}
	if len(s) == 0 || s[0] != ')' {
		return nil, nil, fmt.Errorf("Expecting ) at end of group of queries, but had '%v'", string(s))
	}
	return s, result, nil
}
