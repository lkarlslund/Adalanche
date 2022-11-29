package query

import (
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	timespan "github.com/lkarlslund/time-timespan"
)

type NodeFilter interface {
	Evaluate(o *engine.Object) bool
	ToLDAPFilter() string
	ToWhereClause() string
}

type FilterObjectType struct {
	t engine.ObjectType
}

func (fot FilterObjectType) Evaluate(o *engine.Object) bool {
	return o.Type() == fot.t
}

func (fot FilterObjectType) ToLDAPFilter() string {
	return "(objectType=" + fot.t.String() + ")"
}

func (fot FilterObjectType) ToWhereClause() string {
	return ":" + fot.t.String()
}

// Wraps one Attribute around a queryattribute interface
type FilterOneAttribute struct {
	a engine.Attribute
	q FilterAttribute
}

func (qoa FilterOneAttribute) Evaluate(o *engine.Object) bool {
	return qoa.q.Evaluate(qoa.a, o)
}

func (qoa FilterOneAttribute) ToLDAPFilter() string {
	return qoa.q.ToLDAPFilter(qoa.a.String())
}

func (qoa FilterOneAttribute) ToWhereClause() string {
	return qoa.q.ToWhereClause(qoa.a.String())
}

// Wraps one Attribute around a queryattribute interface
type FilterMultipleAttributes struct {
	attrglobstr string
	a           []engine.Attribute
	q           FilterAttribute
}

func (qma FilterMultipleAttributes) Evaluate(o *engine.Object) bool {
	for _, a := range qma.a {
		if qma.q.Evaluate(a, o) {
			return true
		}
	}
	return false
}

func (qma FilterMultipleAttributes) ToLDAPFilter() string {
	return qma.q.ToLDAPFilter(qma.attrglobstr)
}

func (qma FilterMultipleAttributes) ToWhereClause() string {
	return qma.q.ToWhereClause(qma.attrglobstr)
}

// Wraps any attribute around a queryattribute interface
type FilterAnyAttribute struct {
	q FilterAttribute
}

func (qaa FilterAnyAttribute) Evaluate(o *engine.Object) bool {
	var result bool
	o.AttrIterator(func(attr engine.Attribute, avs engine.AttributeValues) bool {
		if qaa.q.Evaluate(attr, o) {
			result = true
			return false // break
		}
		return true
	})
	return result
}

func (qaa FilterAnyAttribute) ToLDAPFilter() string {
	return "*" + qaa.q.ToLDAPFilter("*")
}

func (qaa FilterAnyAttribute) ToWhereClause() string {
	return "*" + qaa.q.ToWhereClause("*")
}

type FilterAttribute interface {
	Evaluate(a engine.Attribute, o *engine.Object) bool
	ToLDAPFilter(a string) string
	ToWhereClause(a string) string
}

// type ObjectStrings interface {
// 	Strings(o *engine.Object) []string
// }

// type ObjectInt interface {
// 	Int(o *engine.Object) (int64, bool)
// }

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

func (c comparatortype) String() string {
	switch c {
	case CompareEquals:
		return "="
	case CompareLessThan:
		return "<"
	case CompareLessThanEqual:
		return "<="
	case CompareGreaterThan:
		return ">"
	case CompareGreaterThanEqual:
		return ">="
	}
	return "UNKNOWN_COMPARATOR"
}

type LowerStringAttribute engine.Attribute

func (a LowerStringAttribute) Strings(o *engine.Object) []string {
	l := o.AttrRendered(engine.Attribute(a))
	lo := make([]string, l.Len())
	var i int
	l.Iterate(func(s engine.AttributeValue) bool {
		lo[i] = strings.ToLower(s.String())
		i++
		return true
	})
	return lo
}

type andquery struct {
	subitems []NodeFilter
}

func (q andquery) Evaluate(o *engine.Object) bool {
	for _, query := range q.subitems {
		if !query.Evaluate(o) {
			return false
		}
	}
	return true
}

func (q andquery) ToLDAPFilter() string {
	result := "&"
	for _, query := range q.subitems {
		result += query.ToLDAPFilter()
	}
	return result
}

func (q andquery) ToWhereClause() string {
	var result string
	for i, query := range q.subitems {
		if i > 0 {
			result += " AND "
		}
		result += " " + query.ToWhereClause()
	}
	return result
}

type orquery struct {
	subitems []NodeFilter
}

func (q orquery) Evaluate(o *engine.Object) bool {
	for _, query := range q.subitems {
		if query.Evaluate(o) {
			return true
		}
	}
	return false
}

func (q orquery) ToLDAPFilter() string {
	result := "|"
	for _, query := range q.subitems {
		result += query.ToLDAPFilter()
	}
	return result
}

func (q orquery) ToWhereClause() string {
	result := "("
	for i, query := range q.subitems {
		if i > 0 {
			result += " OR "
		}
		result += " " + query.ToWhereClause()
	}
	result += ")"
	return result
}

type NotQuery struct {
	subitem NodeFilter
}

func (q NotQuery) Evaluate(o *engine.Object) bool {
	return !q.subitem.Evaluate(o)
}

func (q NotQuery) ToLDAPFilter() string {
	return "!(" + q.subitem.ToLDAPFilter() + ")"
}

func (q NotQuery) ToWhereClause() string {
	return "UNSUPPORTED!!"
}

type CountModifier struct {
	c     comparatortype
	value int64
}

func (cm CountModifier) Evaluate(a engine.Attribute, o *engine.Object) bool {
	vals, found := o.Get(a)
	count := 0
	if found {
		count = vals.Len()
	}
	return cm.c.Compare(int64(count), cm.value)
}

func (cm CountModifier) ToLDAPFilter(a string) string {
	return a + ":count: " + cm.c.String() + " " + strconv.FormatInt(cm.value, 10)
}

func (cm CountModifier) ToWhereClause(a string) string {
	return "COUNT(" + a + ")" + cm.c.String() + " " + strconv.FormatInt(cm.value, 10)
}

type LengthModifier struct {
	c     comparatortype
	value int64
}

func (lm LengthModifier) Evaluate(a engine.Attribute, o *engine.Object) bool {
	vals, found := o.Get(a)
	if !found {
		return lm.c.Compare(0, lm.value)
	}
	var result bool
	vals.Iterate(func(value engine.AttributeValue) bool {
		if lm.c.Compare(int64(len(value.String())), lm.value) {
			result = true
			return false
		}
		return true
	})
	return result
}

func (lm LengthModifier) ToLDAPFilter(a string) string {
	return a + ":length: " + lm.c.String() + " " + strconv.FormatInt(lm.value, 10)
}

func (lm LengthModifier) ToWhereClause(a string) string {
	return "LENGTH(" + a + ")" + lm.c.String() + " " + strconv.FormatInt(lm.value, 10)
}

type SinceModifier struct {
	c  comparatortype
	ts *timespan.Timespan
}

func (sm SinceModifier) Evaluate(a engine.Attribute, o *engine.Object) bool {
	vals, found := o.Get(a)
	if !found {
		return false
	}

	var result bool
	vals.Iterate(func(value engine.AttributeValue) bool {
		avt, ok := value.(engine.AttributeValueTime)

		if !ok {
			result = false
			return false // break
		}

		t := time.Time(avt)

		if sm.c.Compare(t.Unix(), sm.ts.From(time.Now()).Unix()) {
			result = true
			return false // break
		}

		// Next
		return true
	})
	return result
}

func (sm SinceModifier) ToLDAPFilter(a string) string {
	return a + ":since: " + sm.c.String() + " " + sm.ts.String()
}

func (sm SinceModifier) ToWhereClause(a string) string {
	return "SINCE(" + a + ")" + sm.c.String() + " " + sm.ts.String()
}

type TimediffModifier struct {
	a2 engine.Attribute
	c  comparatortype
	ts *timespan.Timespan
}

func (td TimediffModifier) Evaluate(a engine.Attribute, o *engine.Object) bool {
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

	var result bool
	var i int
	val1s.Iterate(func(value1 engine.AttributeValue) bool {
		t1, ok := value1.Raw().(time.Time)
		if !ok {
			return true // break
		}

		var t2 time.Time
		var t2ok bool
		// Jump to the right entry to evaluate
		var j int
		val2s.Iterate(func(maybeVal2 engine.AttributeValue) bool {
			if i == j {
				t2, t2ok = maybeVal2.Raw().(time.Time)
				return false
			}
			j++
			return true
		})
		if !t2ok {
			return false // break
		}

		if td.c.Compare(t1.Unix(), td.ts.From(t2).Unix()) {
			result = true
			return false // break
		}
		i++
		return true // next
	})
	return result
}

func (td TimediffModifier) ToLDAPFilter(a string) string {
	return a + ":timediff(" + td.a2.String() + "): " + td.c.String() + td.ts.String()
}

func (td TimediffModifier) ToWhereClause(a string) string {
	return "TIMEIDFF(" + a + "," + td.a2.String() + ")" + td.c.String() + td.ts.String()
}

type BinaryAndModifier struct {
	value int64
}

func (am BinaryAndModifier) Evaluate(a engine.Attribute, o *engine.Object) bool {
	val, ok := o.AttrInt(a)
	if !ok {
		return false
	}
	return (int64(val) & am.value) == am.value
}

func (am BinaryAndModifier) ToLDAPFilter(a string) string {
	return a + ":and:=" + strconv.FormatInt(am.value, 10)
}

func (am BinaryAndModifier) ToWhereClause(a string) string {
	return a + " && " + strconv.FormatInt(am.value, 10) + "=" + strconv.FormatInt(am.value, 10)
}

type BinaryOrModifier struct {
	value int64
}

func (om BinaryOrModifier) Evaluate(a engine.Attribute, o *engine.Object) bool {
	val, ok := o.AttrInt(a)
	if !ok {
		return false
	}
	return int64(val)&om.value != 0
}

func (om BinaryOrModifier) ToLDAPFilter(a string) string {
	return a + ":or:=" + strconv.FormatInt(om.value, 10)
}

func (om BinaryOrModifier) ToWhereClause(a string) string {
	return a + " || " + strconv.FormatInt(om.value, 10) + "=" + strconv.FormatInt(om.value, 10)
}

type IntegerComparison struct {
	c     comparatortype
	value int64
}

func (nc IntegerComparison) Evaluate(a engine.Attribute, o *engine.Object) bool {
	val, _ := o.AttrInt(a)
	return nc.c.Compare(val, nc.value)
}

func (nc IntegerComparison) ToLDAPFilter(a string) string {
	return a + nc.c.String() + strconv.FormatInt(nc.value, 10)
}

func (nc IntegerComparison) ToWhereClause(a string) string {
	return a + nc.c.String() + strconv.FormatInt(nc.value, 10)
}

type id struct {
	c     comparatortype
	idval int64
}

func (i *id) Evaluate(o *engine.Object) bool {
	return i.c.Compare(int64(o.ID()), i.idval)
}

func (i *id) ToLDAPFilter() string {
	return "id" + i.c.String() + strconv.FormatInt(i.idval, 10)
}

func (i *id) ToWhereClause() string {
	return "id" + i.c.String() + strconv.FormatInt(i.idval, 10)
}

type limit struct {
	counter int64
}

func (l *limit) Evaluate(o *engine.Object) bool {
	l.counter--
	return l.counter >= 0
}

func (l *limit) ToLDAPFilter() string {
	return "_limit=" + strconv.FormatInt(l.counter, 10)
}

func (l *limit) ToWhereClause() string {
	return "_limit=" + strconv.FormatInt(l.counter, 10)
}

type random100 struct {
	c comparatortype
	v int64
}

func (r random100) Evaluate(o *engine.Object) bool {
	rnd := rand.Int63n(100)
	return r.c.Compare(rnd, r.v)
}

func (r random100) ToLDAPFilter() string {
	return "random100" + r.c.String() + strconv.FormatInt(r.v, 10)
}

func (r random100) ToWhereClause() string {
	return "RANDOM(100)" + r.c.String() + strconv.FormatInt(r.v, 10)
}

type hasAttr struct{}

func (ha hasAttr) Evaluate(a engine.Attribute, o *engine.Object) bool {
	vals, found := o.Get(engine.Attribute(a))
	if !found {
		return false
	}
	return vals.Len() > 0
}

func (ha hasAttr) ToLDAPFilter(a string) string {
	return a + ":count:>0"
}

func (ha hasAttr) ToWhereClause(a string) string {
	return "COUNT(" + a + ")>0"
}

type hasStringMatch struct {
	casesensitive bool
	m             string
}

func (hsm hasStringMatch) Evaluate(a engine.Attribute, o *engine.Object) bool {
	var result bool
	o.AttrRendered(a).Iterate(func(value engine.AttributeValue) bool {
		if !hsm.casesensitive {
			if strings.EqualFold(hsm.m, value.String()) {
				result = true
				return false // break
			}
		} else {
			if hsm.m == value.String() {
				result = true
				return false // break
			}
		}
		return true // continue
	})
	return result
}

func (hsm hasStringMatch) ToLDAPFilter(a string) string {
	if hsm.casesensitive {
		return a + "=" + hsm.m
	} else {
		return a + ":caseinsensitive:=" + hsm.m
	}
}

func (hsm hasStringMatch) ToWhereClause(a string) string {
	return a + "=" + hsm.m
}

type hasGlobMatch struct {
	casesensitive bool
	globstr       string
	m             glob.Glob
}

func (hgm hasGlobMatch) Evaluate(a engine.Attribute, o *engine.Object) bool {
	var result bool
	o.AttrRendered(a).Iterate(func(value engine.AttributeValue) bool {
		if !hgm.casesensitive {
			if hgm.m.Match(strings.ToLower(value.String())) {
				result = true
				return false // break
			}
		} else {
			if hgm.m.Match(value.String()) {
				result = true
				return false // break
			}
		}
		return true // next
	})
	return result
}

func (hgm hasGlobMatch) ToLDAPFilter(a string) string {
	return a + ":glob:=" + hgm.globstr
}

func (hgm hasGlobMatch) ToWhereClause(a string) string {
	return "GLOB(" + a + "," + hgm.globstr + ")"
}

type hasRegexpMatch struct {
	m *regexp.Regexp
}

func (hrm hasRegexpMatch) Evaluate(a engine.Attribute, o *engine.Object) (result bool) {
	o.AttrRendered(a).Iterate(func(value engine.AttributeValue) bool {
		if hrm.m.MatchString(value.String()) {
			result = true
			return false // break
		}
		return true // next
	})
	return
}

func (hrm hasRegexpMatch) ToLDAPFilter(a string) string {
	return a + "=/" + hrm.m.String() + "/"
}

func (hrm hasRegexpMatch) ToWhereClause(a string) string {
	return "REGEXP(" + a + ", " + hrm.m.String() + ")"
}

type recursiveDNmatcher struct {
	dn string
	ao *engine.Objects
}

func (rdn recursiveDNmatcher) Evaluate(a engine.Attribute, o *engine.Object) bool {
	return recursiveDNmatchFunc(o, a, rdn.dn, 10, rdn.ao)
}

func (rdn recursiveDNmatcher) ToLDAPFilter(a string) string {
	return a + ":recursiveDN:=" + rdn.dn
}

func (rdn recursiveDNmatcher) ToWhereClause(a string) string {
	return "RECURSIVEDNMATCH(" + a + ", " + rdn.dn + ")"
}

func recursiveDNmatchFunc(o *engine.Object, a engine.Attribute, dn string, maxdepth int, ao *engine.Objects) (result bool) {
	// Just to prevent loops
	if maxdepth == 0 {
		return false
	}
	// Check all attribute values for match or ancestry
	o.AttrRendered(a).Iterate(func(value engine.AttributeValue) bool {
		// We're at the end
		if strings.EqualFold(value.String(), dn) {
			result = true
			return false // break
		}
		// Perhaps parent matches?
		if parent, found := ao.Find(activedirectory.DistinguishedName, engine.AttributeValueString(value.String())); found {
			result = recursiveDNmatchFunc(parent, a, dn, maxdepth-1, ao)
			return false // break
		}
		return true // next
	})
	return
}

type edgeQuery struct {
	direction engine.EdgeDirection
	edge      engine.Edge
	target    NodeFilter
}

func (p edgeQuery) Evaluate(o *engine.Object) bool {
	var result bool
	o.Edges(p.direction).Range(func(target *engine.Object, edge engine.EdgeBitmap) bool {
		if (p.edge == engine.AnyEdgeType && !edge.IsBlank()) || edge.IsSet(p.edge) {
			if p.target == nil || p.target.Evaluate(target) {
				result = true
				return false // return from loop
			}
		}
		return true
	})
	return result
}

func (p edgeQuery) ToLDAPFilter() string {
	var result string
	if p.direction == engine.Out {
		result += "out"
	} else {
		result += "in"
	}
	result += "=" + p.edge.String()
	if p.target != nil {
		result += "(" + p.target.ToLDAPFilter() + ")"
	}
	return result
}

func (p edgeQuery) ToWhereClause() string {
	var result string
	if p.direction == engine.Out {
		result += "out"
	} else {
		result += "in"
	}
	result += "=" + p.edge.String()
	if p.target != nil {
		result += "(" + p.target.ToWhereClause() + ")"
	}
	return result
}
