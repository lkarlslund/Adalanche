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
	"github.com/gobwas/glob/util/runes"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	timespan "github.com/lkarlslund/time-timespan"
)

type Query interface {
	Evaluate(o *engine.Object) bool
}

// Wraps one Attribute around a queryattribute interface
type QueryOneAttribute struct {
	a engine.Attribute
	q QueryAttribute
}

func (qoa QueryOneAttribute) Evaluate(o *engine.Object) bool {
	return qoa.q.Evaluate(qoa.a, o)
}

// Wraps one Attribute around a queryattribute interface
type QueryMultipleAttributes struct {
	a []engine.Attribute
	q QueryAttribute
}

func (qma QueryMultipleAttributes) Evaluate(o *engine.Object) bool {
	for _, a := range qma.a {
		if qma.q.Evaluate(a, o) {
			return true
		}
	}
	return false
}

// Wraps any attribute around a queryattribute interface
type QueryAnyAttribute struct {
	q QueryAttribute
}

func (qaa QueryAnyAttribute) Evaluate(o *engine.Object) bool {
	for a, _ := range o.AttributeValueMap() {
		if qaa.q.Evaluate(a, o) {
			return true
		}
	}
	return false
}

type QueryAttribute interface {
	Evaluate(a engine.Attribute, o *engine.Object) bool
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

func ParseQueryStrict(s string, ao *engine.Objects) (Query, error) {
	s, query, err := ParseQuery(s, ao)
	if err == nil && s != "" {
		return nil, fmt.Errorf("Extra data after query parsing: %v", s)
	}
	return query, err
}

func ParseQuery(s string, ao *engine.Objects) (string, Query, error) {
	qs, q, err := parseRuneQuery([]rune(s), ao)
	return string(qs), q, err
}

func parseRuneQuery(s []rune, ao *engine.Objects) ([]rune, Query, error) {
	if len(s) < 5 {
		return nil, nil, errors.New("Query string too short")
	}
	if !runes.HasPrefix(s, []rune("(")) || !runes.HasSuffix(s, []rune(")")) {
		return nil, nil, errors.New("Query must start with ( and end with )")
	}
	// Strip (
	s = s[1:]
	var subqueries []Query
	var query Query
	var err error
	switch s[0] {
	case '(': // double wrapped query?
		s, query, err = parseRuneQuery(s, ao)
		if err != nil {
			return nil, nil, err
		}
		if len(s) == 0 {
			return nil, nil, errors.New("Missing closing ) in query")
		}
		// Strip )
		return s[1:], query, nil
	case '&':
		s, subqueries, err = parseMultipleRuneQueries(s[1:], ao)
		if err != nil {
			return nil, nil, err
		}
		// Strip )
		return s[1:], andquery{subqueries}, nil
	case '|':
		s, subqueries, err = parseMultipleRuneQueries(s[1:], ao)
		if err != nil {
			return nil, nil, err
		}
		if len(s) == 0 {
			return nil, nil, errors.New("Query should end with )")
		}
		// Strip )
		return s[1:], orquery{subqueries}, nil
	case '!':
		s, query, err = parseRuneQuery(s[1:], ao)
		if err != nil {
			return nil, nil, err
		}
		if len(s) == 0 {
			return nil, nil, errors.New("Query ends with exclamation mark")
		}
		return s[1:], notquery{query}, err
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
	} else if attributename[0] == '_' {
		// Magic attributes, uuuuuh ....
		switch attributename {
		case "_id":
			if numok != nil {
				return nil, nil, errors.New("Could not convert value to integer for id comparison")
			}
			return s, &id{comparator, valuenum}, nil
		case "_limit":
			if numok != nil {
				return nil, nil, errors.New("Could not convert value to integer for limit limiter")
			}
			return s, &limit{valuenum}, nil
		case "_random100":
			if numok != nil {
				return nil, nil, errors.New("Could not convert value to integer for random100 limiter")
			}
			return s, &random100{comparator, valuenum}, nil
		case "_pwnable", "_canpwn":
			pwnmethod := value
			var target Query
			commapos := strings.Index(pwnmethod, ",")
			if commapos != -1 {
				pwnmethod = value[:commapos]
				target, err = ParseQueryStrict(value[commapos+1:], ao)
				if err != nil {
					return nil, nil, fmt.Errorf("Could not parse sub-query: %v", err)
				}
			}
			var method engine.PwnMethod
			if pwnmethod == "*" {
				method = engine.AnyPwnMethod
			} else {
				method = engine.P(pwnmethod)
				if method == engine.NonExistingPwnMethod {
					return nil, nil, fmt.Errorf("Could not convert value %v to pwn method", pwnmethod)
				}
			}
			return s, pwnquery{attributename == "_canpwn", method, target}, nil
			// default:
			// 	return "", nil, fmt.Errorf("Unknown synthetic attribute %v", attributename)
		}
	} else {
		attribute := engine.A(attributename)
		if attribute == engine.NonExistingAttribute {
			return nil, nil, fmt.Errorf("Unknown attribute %v", attributename)
		}
		attributes = []engine.Attribute{attribute}
	}

	attribute2 := engine.NonExistingAttribute
	if attributename2 != "" {
		attribute2 = engine.A(attributename2)
		if attribute2 == engine.NonExistingAttribute {
			return nil, nil, fmt.Errorf("Unknown attribute %v", attributename2)
		}
	}

	var casesensitive bool

	var genwrapper func(aq QueryAttribute) Query

	switch len(attributes) {
	case 0:
		genwrapper = func(aq QueryAttribute) Query {
			return QueryAnyAttribute{aq}
		}
	case 1:
		genwrapper = func(aq QueryAttribute) Query {
			return QueryOneAttribute{attributes[0], aq}
		}
	default:
		genwrapper = func(aq QueryAttribute) Query {
			return QueryMultipleAttributes{attributes, aq}
		}
	}

	// Decide what to do
	switch modifier {
	case "":
		// That's OK, this is default :-)
	case "caseExactMatch":
		casesensitive = true
	case "count":
		if numok != nil {
			return nil, nil, errors.New("Could not convert value to integer for modifier comparison")
		}
		return s, genwrapper(countModifier{comparator, valuenum}), nil
	case "len", "length":
		if numok != nil {
			return nil, nil, errors.New("Could not convert value to integer for modifier comparison")
		}
		return s, genwrapper(lengthModifier{comparator, valuenum}), nil
	case "since":
		if numok != nil {
			// try to parse it as an duration
			duration, err := timespan.ParseTimespan(value)
			if err != nil {
				return nil, nil, errors.New("Could not parse value as a duration (5h2m)")
			}
			return s, genwrapper(sinceModifier{comparator, duration}), nil
		}
		duration, err := timespan.ParseTimespan(fmt.Sprintf("%vs", valuenum))
		if err != nil {
			return nil, nil, errors.New("Could not parse value as a duration of seconds (5h2m)")
		}
		return s, genwrapper(sinceModifier{comparator, duration}), nil
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
			return s, genwrapper(timediffModifier{attribute2, comparator, duration}), nil
		}
		duration, err := timespan.ParseTimespan(fmt.Sprintf("%vs", valuenum))
		if err != nil {
			return nil, nil, errors.New("Could not parse value as a duration of seconds (5h2m)")
		}
		return s, genwrapper(timediffModifier{attribute2, comparator, duration}), nil

	case "1.2.840.113556.1.4.803", "and":
		if comparator != CompareEquals {
			return nil, nil, errors.New("Modifier 1.2.840.113556.1.4.803 requires equality comparator")
		}
		return s, genwrapper(andModifier{valuenum}), nil
	case "1.2.840.113556.1.4.804", "or":
		if comparator != CompareEquals {
			return nil, nil, errors.New("Modifier 1.2.840.113556.1.4.804 requires equality comparator")
		}
		return s, genwrapper(orModifier{valuenum}), nil
	case "1.2.840.113556.1.4.1941", "dnchain":
		// Matching rule in chain
		return s, genwrapper(recursiveDNmatcher{value, ao}), nil
	default:
		return nil, nil, errors.New("Unknown modifier " + modifier)
	}

	// string comparison
	if comparator == CompareEquals {
		if value == "*" {
			return s, genwrapper(hasAttr{}), nil
		}
		if strings.HasPrefix(value, "/") && strings.HasSuffix(value, "/") {
			// regexp magic
			pattern := value[1 : len(value)-1]
			r, err := regexp.Compile(pattern)
			if err != nil {
				return nil, nil, err
			}
			return s, genwrapper(hasRegexpMatch{r}), nil
		}
		if strings.ContainsAny(value, "?*") {
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
				return s, genwrapper(hasGlobMatch{true, g}), nil
			}
			return s, genwrapper(hasGlobMatch{false, g}), nil
		}
		return s, genwrapper(hasStringMatch{casesensitive, value}), nil
	}

	// the other comparators require numeric value
	if numok != nil {
		return nil, nil, errors.New("Could not convert value to integer for numeric comparison")
	}

	return s, genwrapper(numericComparator{comparator, valuenum}), nil
}

func parseMultipleRuneQueries(s []rune, ao *engine.Objects) ([]rune, []Query, error) {
	var result []Query
	for len(s) > 0 && s[0] == '(' {
		var query Query
		var err error
		s, query, err = parseRuneQuery(s, ao)
		if err != nil {
			return s, nil, err
		}
		result = append(result, query)
	}
	if len(s) == 0 || s[0] != ')' {
		return nil, nil, fmt.Errorf("Expecting ) at end of group of queries, but had '%v'", s)
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
	c     comparatortype
	value int64
}

func (cm countModifier) Evaluate(a engine.Attribute, o *engine.Object) bool {
	vals, found := o.Get(a)
	count := 0
	if found {
		count = vals.Len()
	}
	return cm.c.Compare(int64(count), cm.value)
}

type lengthModifier struct {
	c     comparatortype
	value int64
}

func (lm lengthModifier) Evaluate(a engine.Attribute, o *engine.Object) bool {
	vals, found := o.Get(a)
	if !found {
		return lm.c.Compare(0, lm.value)
	}
	for _, value := range vals.StringSlice() {
		if lm.c.Compare(int64(len(value)), lm.value) {
			return true
		}
	}
	return false
}

type sinceModifier struct {
	c  comparatortype
	ts *timespan.Timespan
}

func (sm sinceModifier) Evaluate(a engine.Attribute, o *engine.Object) bool {
	vals, found := o.Get(a)
	if !found {
		return false
	}

	for _, value := range vals.Slice() {
		// Time in AD is either a

		raw := value.Raw()

		t, ok := raw.(time.Time)

		if !ok {
			return false
		}

		if sm.c.Compare(sm.ts.From(t).Unix(), time.Now().Unix()) {
			return true
		}
	}
	return false
}

type timediffModifier struct {
	a2 engine.Attribute
	c  comparatortype
	ts *timespan.Timespan
}

func (td timediffModifier) Evaluate(a engine.Attribute, o *engine.Object) bool {
	val1s, found := o.Get(a)
	if !found {
		return false
	}

	val2s, found := o.Get(td.a2)
	if !found {
		return false
	}

	if val1s.Len() != val2s.Len() {
		return false
	}

	val2slice := val2s.Slice()
	for i, value1 := range val1s.Slice() {
		t1, ok := value1.Raw().(time.Time)
		if !ok {
			continue
		}

		t2, ok2 := val2slice[i].Raw().(time.Time)
		if !ok2 {
			continue
		}

		if td.c.Compare(t1.Unix(), td.ts.From(t2).Unix()) {
			return true
		}
	}
	return false
}

type andModifier struct {
	value int64
}

func (am andModifier) Evaluate(a engine.Attribute, o *engine.Object) bool {
	val, ok := o.AttrInt(a)
	if !ok {
		return false
	}
	return (int64(val) & am.value) == am.value
}

type orModifier struct {
	value int64
}

func (om orModifier) Evaluate(a engine.Attribute, o *engine.Object) bool {
	val, ok := o.AttrInt(a)
	if !ok {
		return false
	}
	return int64(val)&om.value != 0
}

type numericComparator struct {
	c     comparatortype
	value int64
}

func (nc numericComparator) Evaluate(a engine.Attribute, o *engine.Object) bool {
	val, _ := o.AttrInt(a)
	return nc.c.Compare(val, nc.value)
}

type id struct {
	c     comparatortype
	idval int64
}

func (i *id) Evaluate(o *engine.Object) bool {
	return i.c.Compare(int64(o.ID()), i.idval)
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

type hasAttr struct{}

func (ha hasAttr) Evaluate(a engine.Attribute, o *engine.Object) bool {
	vals, found := o.Get(engine.Attribute(a))
	if !found {
		return false
	}
	return vals.Len() > 0
}

type hasStringMatch struct {
	casesensitive bool
	m             string
}

func (hsm hasStringMatch) Evaluate(a engine.Attribute, o *engine.Object) bool {
	for _, value := range o.AttrRendered(a) {
		if !hsm.casesensitive {
			if strings.EqualFold(hsm.m, value) {
				return true
			}
		} else {
			if hsm.m == value {
				return true
			}
		}
	}
	return false
}

type hasGlobMatch struct {
	casesensitive bool
	m             glob.Glob
}

func (hgm hasGlobMatch) Evaluate(a engine.Attribute, o *engine.Object) bool {
	for _, value := range o.AttrRendered(a) {
		if !hgm.casesensitive {
			if hgm.m.Match(strings.ToLower(value)) {
				return true
			}
		} else {
			if hgm.m.Match(value) {
				return true
			}
		}
	}
	return false
}

type hasRegexpMatch struct {
	m *regexp.Regexp
}

func (hrm hasRegexpMatch) Evaluate(a engine.Attribute, o *engine.Object) bool {
	for _, value := range o.AttrRendered(a) {
		if hrm.m.MatchString(value) {
			return true
		}
	}
	return false
}

type recursiveDNmatcher struct {
	dn string
	ao *engine.Objects
}

func (rdn recursiveDNmatcher) Evaluate(a engine.Attribute, o *engine.Object) bool {
	return recursiveDNmatchFunc(o, a, rdn.dn, 10, rdn.ao)
}

func recursiveDNmatchFunc(o *engine.Object, a engine.Attribute, dn string, maxdepth int, ao *engine.Objects) bool {
	// Just to prevent loops
	if maxdepth == 0 {
		return false
	}
	// Check all attribute values for match or ancestry
	for _, value := range o.AttrRendered(a) {
		// We're at the end
		if strings.EqualFold(value, dn) {
			return true
		}
		// Perhaps parent matches?
		if parent, found := ao.Find(activedirectory.DistinguishedName, engine.AttributeValueString(value)); found {
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
	for pwntarget, pwnmethod := range items {
		if (p.method == engine.AnyPwnMethod && pwnmethod.Count() != 0) || pwnmethod.IsSet(p.method) {
			if p.target == nil || p.target.Evaluate(pwntarget) {
				return true
			}
		}
	}
	return false
}
