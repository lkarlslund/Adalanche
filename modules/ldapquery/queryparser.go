package ldapquery

import (
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/util"
	timespan "github.com/lkarlslund/time-timespan"
	"github.com/rs/zerolog/log"
)

type Query interface {
	Evaluate(o *engine.Object) bool
}

type ObjectStrings interface {
	Strings(o *engine.Object) []string
}

type ObjectInt interface {
	Int(o *engine.Object) (int64, bool)
}

type comparatortype byte

const (
	CompareEquals comparatortype = iota
	CompareLessThan
	CompareLessThanEqual
	CompareGreaterThan
	CompareGreaterThanEqual
)

func (c comparatortype) Compare(a, b int64) bool {
	switch c {
	case CompareEquals:
		return a == b
	case CompareLessThan:
		return a < b
	case CompareLessThanEqual:
		return a <= b
	case CompareGreaterThan:
		return a > b
	case CompareGreaterThanEqual:
		return a >= b
	}
	return false // I hope not
}

type LowerStringAttribute engine.Attribute

func (a LowerStringAttribute) Strings(o *engine.Object) []string {
	l := o.AttrRendered(engine.Attribute(a))
	for i, s := range l {
		l[i] = strings.ToLower(s)
	}
	return l
}

type QueryAttribute engine.Attribute

func (a QueryAttribute) Strings(o *engine.Object) []string {
	return o.AttrRendered(engine.Attribute(a))
}

func (a QueryAttribute) Ints(o *engine.Object) (int64, bool) {
	return o.AttrInt(engine.Attribute(a))
}

func ParseQueryStrict(s string, ao *engine.Objects) (Query, error) {
	s, query, err := ParseQuery(s, ao)
	if err == nil && s != "" {
		return nil, fmt.Errorf("Extra data after query parsing: %v", s)
	}
	return query, err
}

func ParseQuery(s string, ao *engine.Objects) (string, Query, error) {
	if len(s) < 5 {
		return "", nil, errors.New("Query string too short")
	}
	if !strings.HasPrefix(s, "(") || !strings.HasSuffix(s, ")") {
		return "", nil, errors.New("Query must start with ( and end with )")
	}
	// Strip (
	s = s[1:]
	var subqueries []Query
	var query Query
	var err error
	switch s[0] {
	case '(': // double wrapped query?
		s, query, err = ParseQuery(s, ao)
		if err != nil {
			return "", nil, err
		}
		if len(s) == 0 {
			return "", nil, errors.New("Missing closing ) in query")
		}
		// Strip )
		return s[1:], query, nil
	case '&':
		s, subqueries, err = parsemultiplequeries(s[1:], ao)
		if err != nil {
			return "", nil, err
		}
		// Strip )
		return s[1:], andquery{subqueries}, nil
	case '|':
		s, subqueries, err = parsemultiplequeries(s[1:], ao)
		if err != nil {
			return "", nil, err
		}
		// Strip )
		return s[1:], orquery{subqueries}, nil
	case '!':
		s, query, err = ParseQuery(s[1:], ao)
		if err != nil {
			return "", nil, err
		}
		return s[1:], notquery{query}, err
	}

	// parse one Attribute = Value pair
	var modifier string
	var attributename string

	// Attribute name
attributeloop:
	for {
		if len(s) == 0 {
			return "", nil, errors.New("Incompete query attribute name detected")
		}
		switch s[0] {
		case '\\': // Escaping
			attributename += string(s[1])
			s = s[2:] // yum yum
		case ':':
			// Modifier
			nextcolon := strings.Index(s[1:], ":")
			if nextcolon == -1 {
				return "", nil, errors.New("Incompete query string detected (only one colon modifier)")
			}
			modifier = s[1 : nextcolon+1]
			s = s[nextcolon+2:]
			break attributeloop
		case ')':
			return "", nil, errors.New("Unexpected closing parantesis")
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
			return "", nil, errors.New("Tilde operator MUST be followed by EQUALS")
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
valueloop:
	for {
		if len(s) == 0 {
			return "", nil, errors.New("Incomplete query value detected")
		}
		switch s[0] {
		case '\\': // Escaping
			value += string(s[1])
			s = s[2:] // yum yum
		case ')':
			break valueloop
		default:
			value += string(s[0])
			s = s[1:]
		}
	}

	// Eat the )
	s = s[1:]

	valuenum, numok := strconv.ParseInt(value, 10, 64)

	if attributename[0] == '_' {
		// Magic attributes, uuuuuh ....
		switch attributename {
		case "_limit":
			if numok != nil {
				return "", nil, errors.New("Could not convert value to integer for limit limiter")
			}
			return s, &limit{valuenum}, nil
		case "_random100":
			if numok != nil {
				return "", nil, errors.New("Could not convert value to integer for random100 limiter")
			}
			return s, &random100{comparator, valuenum}, nil
		case "_pwnable", "_canpwn":
			pwnmethod := value
			var target Query
			if strings.Contains(pwnmethod, ",") {
				values := strings.Split(pwnmethod, ",")
				pwnmethod = values[0]
				target, _ = ParseQueryStrict(values[1], ao)
			}
			var method engine.PwnMethod
			if pwnmethod != "" && pwnmethod != "*" {
				method = engine.P(pwnmethod)
				if method == engine.NonExistingPwnMethod {
					return "", nil, fmt.Errorf("Could not convert value %v to pwn method", pwnmethod)
				}
			}
			return s, pwnquery{attributename == "_canpwn", method, target}, nil
		default:
			return "", nil, fmt.Errorf("Unknown synthetic attribute %v", attributename)
		}
	}

	attribute := engine.A(attributename)
	if attribute == 0 {
		return "", nil, fmt.Errorf("Unknown attribute %v", attributename)
	}

	var casesensitive bool

	// Decide what to do
	switch modifier {
	case "":
		// That's OK, this is default :-)
	case "caseExactMatch":
		casesensitive = true
	case "count":
		if numok != nil {
			return "", nil, errors.New("Could not convert value to integer for modifier comparison")
		}
		return s, countModifier{QueryAttribute(attribute), comparator, valuenum}, nil
	case "len", "length":
		if numok != nil {
			return "", nil, errors.New("Could not convert value to integer for modifier comparison")
		}
		return s, lengthModifier{QueryAttribute(attribute), comparator, valuenum}, nil
	case "since":
		if numok != nil {
			// try to parse it as an duration
			d, err := timespan.ParseTimespan(value)
			timeinseconds := time.Time(timespan.Time(time.Now()).Add(d)).Unix()
			if err != nil {
				return "", nil, errors.New("Could not parse value as a duration (5h2m)")
			}
			return s, sinceModifier{QueryAttribute(attribute), comparator, int64(timeinseconds)}, nil
		}
		return s, lengthModifier{QueryAttribute(attribute), comparator, valuenum}, nil
	case "1.2.840.113556.1.4.803", "and":
		if comparator != CompareEquals {
			return "", nil, errors.New("Modifier 1.2.840.113556.1.4.803 requires equality comparator")
		}
		return s, andModifier{attribute, valuenum}, nil
	case "1.2.840.113556.1.4.804", "or":
		if comparator != CompareEquals {
			return "", nil, errors.New("Modifier 1.2.840.113556.1.4.804 requires equality comparator")
		}
		return s, orModifier{attribute, valuenum}, nil
	case "1.2.840.113556.1.4.1941", "dnchain":
		// Matching rule in chain
		return s, recursiveDNmatcher{attribute, value, ao}, nil
	default:
		return "", nil, errors.New("Unknown modifier " + modifier)
	}

	// string comparison
	if comparator == CompareEquals {
		if value == "*" {
			return s, hasAttr(attribute), nil
		}
		if strings.HasPrefix(value, "/") && strings.HasSuffix(value, "/") {
			// regexp magic
			pattern := value[1 : len(value)-1]
			if !casesensitive {
				pattern = strings.ToLower(pattern)
			}
			r, err := regexp.Compile(pattern)
			if err != nil {
				return "", nil, err
			}
			return s, hasRegexpMatch{QueryAttribute(attribute), r}, nil
		}
		if strings.ContainsAny(value, "?*") {
			// glob magic
			pattern := value
			if !casesensitive {
				pattern = strings.ToLower(pattern)
			}
			g, err := glob.Compile(pattern)
			if err != nil {
				return "", nil, err
			}
			if casesensitive {
				return s, hasGlobMatch{QueryAttribute(attribute), g}, nil
			}
			return s, hasGlobMatch{LowerStringAttribute(attribute), g}, nil
		}
		if casesensitive {
			return s, hasStringMatch{QueryAttribute(attribute), value}, nil
		}
		return s, hasInsensitiveStringMatch{attribute, value}, nil
	}

	// the other comparators require numeric value
	if numok != nil {
		return "", nil, errors.New("Could not convert value to integer for numeric comparison")
	}

	return s, numericComparator{attribute, comparator, valuenum}, nil
}

func parsemultiplequeries(s string, ao *engine.Objects) (string, []Query, error) {
	var result []Query
	for len(s) > 0 && s[0] == '(' {
		var query Query
		var err error
		s, query, err = ParseQuery(s, ao)
		if err != nil {
			return s, nil, err
		}
		result = append(result, query)
	}
	if len(s) == 0 || s[0] != ')' {
		return "", nil, fmt.Errorf("Expecting ) at end of group of queries, but had '%v'", s)
	}
	return s, result, nil
}

type andquery struct {
	subitems []Query
}

func (q andquery) Evaluate(o *engine.Object) bool {
	for _, query := range q.subitems {
		if !query.Evaluate(o) {
			return false
		}
	}
	return true
}

type orquery struct {
	subitems []Query
}

func (q orquery) Evaluate(o *engine.Object) bool {
	for _, query := range q.subitems {
		if query.Evaluate(o) {
			return true
		}
	}
	return false
}

type notquery struct {
	subitem Query
}

func (q notquery) Evaluate(o *engine.Object) bool {
	return !q.subitem.Evaluate(o)
}

type countModifier struct {
	a     ObjectStrings
	c     comparatortype
	value int64
}

func (a countModifier) Evaluate(o *engine.Object) bool {
	return a.c.Compare(int64(len(a.a.Strings(o))), a.value)
}

type lengthModifier struct {
	a     ObjectStrings
	c     comparatortype
	value int64
}

func (a lengthModifier) Evaluate(o *engine.Object) bool {
	for _, value := range a.a.Strings(o) {
		if a.c.Compare(int64(len(value)), a.value) {
			return true
		}
	}
	return false
}

type sinceModifier struct {
	a     ObjectStrings
	c     comparatortype
	value int64 // time in seconds, positive is in the past, negative in the future
}

func (sm sinceModifier) Evaluate(o *engine.Object) bool {
	for _, value := range sm.a.Strings(o) {
		// Time in AD is either a
		var t time.Time
		if strings.HasSuffix(value, ".0Z") && len(value) == 17 {
			pt, err := time.Parse("20060102150405", value[:14])
			if err != nil { // very unlikely, but who knows
				return false
			}
			t = pt
		} else {
			i, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return false
			}
			t = util.FiletimeToTime(uint64(i))
		}
		log.Debug().Msgf("Object %v has %v parsed as %v", o.Label(), value, t.Format(time.RFC1123Z))

		if sm.c.Compare(t.Unix(), sm.value) {
			return true
		}
	}
	return false
}

type andModifier struct {
	a     engine.Attribute
	value int64
}

func (a andModifier) Evaluate(o *engine.Object) bool {
	val, ok := o.AttrInt(a.a)
	if !ok {
		return false
	}
	return (int64(val) & a.value) == a.value
}

type orModifier struct {
	a     engine.Attribute
	value int64
}

func (om orModifier) Evaluate(o *engine.Object) bool {
	val, ok := o.AttrInt(om.a)
	if !ok {
		return false
	}
	return int64(val)&om.value != 0
}

type numericComparator struct {
	a     engine.Attribute
	c     comparatortype
	value int64
}

func (nc numericComparator) Evaluate(o *engine.Object) bool {
	val, _ := o.AttrInt(nc.a)
	// if !ok {
	// 	return false
	// }
	return nc.c.Compare(val, nc.value)
}

type limit struct {
	counter int64
}

func (l *limit) Evaluate(o *engine.Object) bool {
	l.counter--
	return l.counter >= 0
}

type random100 struct {
	c comparatortype
	v int64
}

func (r random100) Evaluate(o *engine.Object) bool {
	rnd := rand.Int63n(100)
	return r.c.Compare(rnd, r.v)
}

type hasAttr QueryAttribute

func (a hasAttr) Evaluate(o *engine.Object) bool {
	return len(QueryAttribute(a).Strings(o)) > 0
}

type hasStringMatch struct {
	a ObjectStrings
	m string
}

func (a hasStringMatch) Evaluate(o *engine.Object) bool {
	for _, value := range a.a.Strings(o) {
		if a.m == value {
			return true
		}
	}
	return false
}

// Need you to lowercase m when creating it!!
type hasInsensitiveStringMatch struct {
	a engine.Attribute
	m string
}

func (a hasInsensitiveStringMatch) Evaluate(o *engine.Object) bool {
	for _, value := range o.AttrRendered(a.a) {
		if strings.EqualFold(a.m, value) {
			return true
		}
	}
	return false
}

type hasGlobMatch struct {
	a ObjectStrings
	m glob.Glob
}

func (a hasGlobMatch) Evaluate(o *engine.Object) bool {
	for _, value := range a.a.Strings(o) {
		if a.m.Match(value) {
			return true
		}
	}
	return false
}

type hasRegexpMatch struct {
	a ObjectStrings
	m *regexp.Regexp
}

func (a hasRegexpMatch) Evaluate(o *engine.Object) bool {
	for _, value := range a.a.Strings(o) {
		if a.m.MatchString(value) {
			return true
		}
	}
	return false
}

type recursiveDNmatcher struct {
	a  engine.Attribute
	dn string
	ao *engine.Objects
}

func (a recursiveDNmatcher) Evaluate(o *engine.Object) bool {
	return recursiveDNmatchFunc(o, a.a, a.dn, 10, a.ao)
}

func recursiveDNmatchFunc(o *engine.Object, a engine.Attribute, dn string, maxdepth int, ao *engine.Objects) bool {
	// Just to prevent loops
	if maxdepth == 0 {
		return false
	}
	// Check all attribute values for match or ancestry
	for _, value := range o.Attr(a).Slice() {
		// We're at the end
		if strings.EqualFold(value.String(), dn) {
			return true
		}
		// Perhaps parent matches?
		if parent, found := ao.Find(engine.DistinguishedName, value); found {
			return recursiveDNmatchFunc(parent, a, dn, maxdepth-1, ao)
		}
	}
	return false
}

type pwnquery struct {
	canpwn bool
	method engine.PwnMethod
	target Query
}

func (p pwnquery) Evaluate(o *engine.Object) bool {
	items := o.CanPwn
	if !p.canpwn {
		items = o.PwnableBy
	}
	for _, pwnmethod := range items {
		if p.method == 0 || pwnmethod.IsSet(p.method) {
			return true
		}
	}
	return false
}

/*
type pwnable PwnMethod

func (p pwnable) Evaluate(o *Object) bool {
	for _, pwnmethod := range o.PwnableBy {
		if pwnmethod.Methods().IsSet(PwnMethod(p)) {
			return true
		}
	}
	return false
}
*/
