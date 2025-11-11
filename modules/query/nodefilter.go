package query

import (
	"cmp"
	"fmt"
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
	Evaluate(o *engine.Node) bool
	ToLDAPFilter() string
	ToWhereClause() string
}
type FilterObjectType struct {
	t engine.NodeType
}

func (fot FilterObjectType) Evaluate(o *engine.Node) bool {
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
	FilterAttribute FilterAttribute
	Attribute       engine.Attribute
}

func (qoa FilterOneAttribute) Evaluate(o *engine.Node) bool {
	return qoa.FilterAttribute.Evaluate(qoa.Attribute, o)
}
func (qoa FilterOneAttribute) ToLDAPFilter() string {
	return qoa.FilterAttribute.ToLDAPFilter(qoa.Attribute.String())
}
func (qoa FilterOneAttribute) ToWhereClause() string {
	return qoa.FilterAttribute.ToWhereClause(qoa.Attribute.String())
}

// Wraps one Attribute around a queryattribute interface
type FilterMultipleAttributes struct {
	FilterAttribute     FilterAttribute
	AttributeGlobString string
	Attributes          []engine.Attribute
}

func (qma FilterMultipleAttributes) Evaluate(o *engine.Node) bool {
	for _, a := range qma.Attributes {
		if qma.FilterAttribute.Evaluate(a, o) {
			return true
		}
	}
	return false
}
func (qma FilterMultipleAttributes) ToLDAPFilter() string {
	return qma.FilterAttribute.ToLDAPFilter(qma.AttributeGlobString)
}
func (qma FilterMultipleAttributes) ToWhereClause() string {
	return qma.FilterAttribute.ToWhereClause(qma.AttributeGlobString)
}

// Wraps any attribute around a queryattribute interface
type FilterAnyAttribute struct {
	Attribute FilterAttribute
}

func (qaa FilterAnyAttribute) Evaluate(o *engine.Node) bool {
	var result bool
	o.AttrIterator(func(attr engine.Attribute, avs engine.AttributeValues) bool {
		if qaa.Attribute.Evaluate(attr, o) {
			result = true
			return false // break
		}
		return true
	})
	return result
}
func (qaa FilterAnyAttribute) ToLDAPFilter() string {
	return "*" + qaa.Attribute.ToLDAPFilter("*")
}
func (qaa FilterAnyAttribute) ToWhereClause() string {
	return "*" + qaa.Attribute.ToWhereClause("*")
}

type FilterAttribute interface {
	Evaluate(a engine.Attribute, o *engine.Node) bool
	ToLDAPFilter(a string) string
	ToWhereClause(a string) string
}

//	type ObjectStrings interface {
//		Strings(o *engine.Object) []string
//	}
//
//	type ObjectInt interface {
//		Int(o *engine.Object) (int64, bool)
//	}
type ComparatorType byte

//go:generate go tool github.com/dmarkham/enumer --type=ComparatorType
const (
	CompareInvalid ComparatorType = iota
	CompareDifferent
	CompareEqual
	CompareLessThan
	CompareLessThanEqual
	CompareGreaterThan
	CompareGreaterThanEqual
)

type Comparator[t cmp.Ordered] ComparatorType

func (c Comparator[t]) Compare(a, b t) bool {
	switch ComparatorType(c) {
	case CompareDifferent:
		return a != b
	case CompareEqual:
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
func (c Comparator[t]) String() string {
	return ComparatorType(c).String()
}

type LowerStringAttribute engine.Attribute

func (a LowerStringAttribute) Strings(o *engine.Node) []string {
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

type AndQuery struct {
	Subitems []NodeFilter
}

func (q AndQuery) Evaluate(o *engine.Node) bool {
	for _, query := range q.Subitems {
		if !query.Evaluate(o) {
			return false
		}
	}
	return true
}
func (q AndQuery) ToLDAPFilter() string {
	result := "&"
	for _, query := range q.Subitems {
		result += query.ToLDAPFilter()
	}
	return result
}
func (q AndQuery) ToWhereClause() string {
	var result string
	for i, query := range q.Subitems {
		if i > 0 {
			result += " AND "
		}
		result += " " + query.ToWhereClause()
	}
	return result
}

type OrQuery struct {
	Subitems []NodeFilter
}

func (q OrQuery) Evaluate(o *engine.Node) bool {
	for _, query := range q.Subitems {
		if query.Evaluate(o) {
			return true
		}
	}
	return false
}
func (q OrQuery) ToLDAPFilter() string {
	result := "|"
	for _, query := range q.Subitems {
		result += query.ToLDAPFilter()
	}
	return result
}
func (q OrQuery) ToWhereClause() string {
	result := "("
	for i, query := range q.Subitems {
		if i > 0 {
			result += " OR "
		}
		result += " " + query.ToWhereClause()
	}
	result += ")"
	return result
}

type NotQuery struct {
	Subitem NodeFilter
}

func (q NotQuery) Evaluate(o *engine.Node) bool {
	return !q.Subitem.Evaluate(o)
}
func (q NotQuery) ToLDAPFilter() string {
	return "!(" + q.Subitem.ToLDAPFilter() + ")"
}
func (q NotQuery) ToWhereClause() string {
	return "UNSUPPORTED!!"
}

type CountModifier struct {
	Comparator ComparatorType
	Value      int
}

func (cm CountModifier) Evaluate(a engine.Attribute, o *engine.Node) bool {
	vals, found := o.Get(a)
	count := 0
	if found {
		count = vals.Len()
	}
	return Comparator[int](cm.Comparator).Compare(count, cm.Value)
}
func (cm CountModifier) ToLDAPFilter(a string) string {
	return a + ":count: " + Comparator[int](cm.Comparator).String() + " " + strconv.Itoa(cm.Value)
}
func (cm CountModifier) ToWhereClause(a string) string {
	return "COUNT(" + a + ")" + Comparator[int](cm.Comparator).String() + " " + strconv.Itoa(cm.Value)
}

type LengthModifier struct {
	Comparator ComparatorType
	Value      int
}

func (lm LengthModifier) Evaluate(a engine.Attribute, o *engine.Node) bool {
	vals, found := o.Get(a)
	if !found {
		return Comparator[int](lm.Comparator).Compare(0, lm.Value)
	}
	var result bool
	vals.Iterate(func(value engine.AttributeValue) bool {
		if Comparator[int](lm.Comparator).Compare(len(value.String()), lm.Value) {
			result = true
			return false
		}
		return true
	})
	return result
}
func (lm LengthModifier) ToLDAPFilter(a string) string {
	return a + ":length: " + lm.Comparator.String() + " " + strconv.Itoa(lm.Value)
}
func (lm LengthModifier) ToWhereClause(a string) string {
	return "LENGTH(" + a + ")" + lm.Comparator.String() + " " + strconv.Itoa(lm.Value)
}

type SinceModifier struct {
	TimeSpan   *timespan.Timespan
	Comparator ComparatorType
}

func (sm SinceModifier) Evaluate(a engine.Attribute, o *engine.Node) bool {
	vals, found := o.Get(a)
	if !found {
		return false
	}
	var result bool
	vals.Iterate(func(value engine.AttributeValue) bool {
		t, ok := value.Raw().(time.Time)
		if !ok {
			result = false
			return false // break
		}
		if Comparator[int64](sm.Comparator).Compare(t.Unix(), sm.TimeSpan.From(time.Now()).Unix()) {
			result = true
			return false // break
		}
		// Next
		return true
	})
	return result
}
func (sm SinceModifier) ToLDAPFilter(a string) string {
	return a + ":since: " + sm.Comparator.String() + " " + sm.TimeSpan.String()
}
func (sm SinceModifier) ToWhereClause(a string) string {
	return "SINCE(" + a + ")" + sm.Comparator.String() + " " + sm.TimeSpan.String()
}

type TimediffModifier struct {
	TimeSpan   *timespan.Timespan
	Attribute2 engine.Attribute
	Comparator ComparatorType
}

func (td TimediffModifier) Evaluate(a engine.Attribute, o *engine.Node) bool {
	val1s, found := o.Get(a)
	if !found {
		return false
	}
	val2s, found := o.Get(td.Attribute2)
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
		if Comparator[int64](td.Comparator).Compare(t1.Unix(), td.TimeSpan.From(t2).Unix()) {
			result = true
			return false // break
		}
		i++
		return true // next
	})
	return result
}
func (td TimediffModifier) ToLDAPFilter(a string) string {
	return a + ":timediff(" + td.Attribute2.String() + "): " + td.Comparator.String() + td.TimeSpan.String()
}
func (td TimediffModifier) ToWhereClause(a string) string {
	return "TIMEIDFF(" + a + "," + td.Attribute2.String() + ")" + td.Comparator.String() + td.TimeSpan.String()
}

type BinaryAndModifier struct {
	Value int64
}

func (am BinaryAndModifier) Evaluate(a engine.Attribute, o *engine.Node) bool {
	val, ok := o.AttrInt(a)
	if !ok {
		return false
	}
	return (int64(val) & am.Value) == am.Value
}
func (am BinaryAndModifier) ToLDAPFilter(a string) string {
	return a + ":and:=" + strconv.FormatInt(am.Value, 10)
}
func (am BinaryAndModifier) ToWhereClause(a string) string {
	return a + " && " + strconv.FormatInt(am.Value, 10) + "=" + strconv.FormatInt(am.Value, 10)
}

type BinaryOrModifier struct {
	Value int64
}

func (om BinaryOrModifier) Evaluate(a engine.Attribute, o *engine.Node) bool {
	val, ok := o.AttrInt(a)
	if !ok {
		return false
	}
	return int64(val)&om.Value != 0
}
func (om BinaryOrModifier) ToLDAPFilter(a string) string {
	return a + ":or:=" + strconv.FormatInt(om.Value, 10)
}
func (om BinaryOrModifier) ToWhereClause(a string) string {
	return a + " || " + strconv.FormatInt(om.Value, 10) + "=" + strconv.FormatInt(om.Value, 10)
}

type AttributeComparison struct {
	Value      engine.AttributeValue
	Comparator ComparatorType
}

func (tc AttributeComparison) Evaluate(a engine.Attribute, o *engine.Node) bool {
	val := o.Attr(a)
	if val == nil {
		return false
	}
	var matched bool
	val.Iterate(func(thisVal engine.AttributeValue) bool {
		comp := thisVal.Compare(tc.Value)
		switch tc.Comparator {
		case CompareDifferent:
			if comp != 0 {
				matched = true
			}
		case CompareEqual:
			if comp == 0 {
				matched = true
			}
		case CompareLessThan:
			if comp < 0 {
				matched = true
			}
		case CompareLessThanEqual:
			if comp <= 0 {
				matched = true
			}
		case CompareGreaterThan:
			if comp > 0 {
				matched = true
			}
		case CompareGreaterThanEqual:
			if comp >= 0 {
				matched = true
			}
		default:
			panic("Unknown comparator")
		}
		if matched {
			return false
		}
		return true
	})
	return matched
}

func (tc AttributeComparison) ToLDAPFilter(a string) string {
	return a + tc.Comparator.String() + fmt.Sprintf("%v", tc.Value)
}
func (tc AttributeComparison) ToWhereClause(a string) string {
	return a + tc.Comparator.String() + fmt.Sprintf("%v", tc.Value)
}

type id struct {
	c     ComparatorType
	idval int64
}

func (i *id) Evaluate(o *engine.Node) bool {
	return Comparator[int64](i.c).Compare(int64(o.ID()), i.idval)
}
func (i *id) ToLDAPFilter() string {
	return "_id" + i.c.String() + strconv.FormatInt(i.idval, 10)
}
func (i *id) ToWhereClause() string {
	return "_id" + i.c.String() + strconv.FormatInt(i.idval, 10)
}

type Limit struct {
	Counter int64
}

func (l *Limit) Evaluate(o *engine.Node) bool {
	l.Counter--
	return l.Counter >= 0
}
func (l *Limit) ToLDAPFilter() string {
	return "_limit=" + strconv.FormatInt(l.Counter, 10)
}
func (l *Limit) ToWhereClause() string {
	return "_limit=" + strconv.FormatInt(l.Counter, 10)
}

type Random100 struct {
	Comparator ComparatorType
	Value      int64
}

func (r Random100) Evaluate(o *engine.Node) bool {
	rnd := rand.Int63n(100)
	return Comparator[int64](r.Comparator).Compare(rnd, r.Value)
}
func (r Random100) ToLDAPFilter() string {
	return "random100" + r.Comparator.String() + strconv.FormatInt(r.Value, 10)
}
func (r Random100) ToWhereClause() string {
	return "RANDOM(100)" + r.Comparator.String() + strconv.FormatInt(r.Value, 10)
}

type HasAttr struct{}

func (ha HasAttr) Evaluate(a engine.Attribute, o *engine.Node) bool {
	vals, found := o.Get(engine.Attribute(a))
	if !found {
		return false
	}
	return vals.Len() > 0
}
func (ha HasAttr) ToLDAPFilter(a string) string {
	return a + ":count:>0"
}
func (ha HasAttr) ToWhereClause(a string) string {
	return "COUNT(" + a + ")>0"
}

type HasStringMatch struct {
	Value         engine.AttributeValue
	Casesensitive bool
}

func (hsm HasStringMatch) Evaluate(a engine.Attribute, o *engine.Node) bool {
	var result bool
	o.AttrRendered(a).Iterate(func(value engine.AttributeValue) bool {
		if !hsm.Casesensitive {
			if strings.EqualFold(hsm.Value.String(), value.String()) {
				result = true
				return false // break
			}
		} else {
			if engine.CompareAttributeValuesInt(value, hsm.Value) == 0 {
				result = true
				return false // break
			}
		}
		return true // continue
	})
	return result
}
func (hsm HasStringMatch) ToLDAPFilter(a string) string {
	if hsm.Casesensitive {
		return a + "=" + hsm.Value.String()
	} else {
		return a + ":caseinsensitive:=" + hsm.Value.String()
	}
}
func (hsm HasStringMatch) ToWhereClause(a string) string {
	return a + "=" + hsm.Value.String()
}

type HasGlobMatch struct {
	Match         glob.Glob
	Globstr       string
	Casesensitive bool
}

func (hgm HasGlobMatch) Evaluate(a engine.Attribute, o *engine.Node) bool {
	var result bool
	o.AttrRendered(a).Iterate(func(value engine.AttributeValue) bool {
		if !hgm.Casesensitive {
			if hgm.Match.Match(strings.ToLower(value.String())) {
				result = true
				return false // break
			}
		} else {
			if hgm.Match.Match(value.String()) {
				result = true
				return false // break
			}
		}
		return true // next
	})
	return result
}
func (hgm HasGlobMatch) ToLDAPFilter(a string) string {
	return a + ":glob:=" + hgm.Globstr
}
func (hgm HasGlobMatch) ToWhereClause(a string) string {
	return "GLOB(" + a + "," + hgm.Globstr + ")"
}

type HasRegexpMatch struct {
	RegExp *regexp.Regexp
}

func (hrm HasRegexpMatch) Evaluate(a engine.Attribute, o *engine.Node) (result bool) {
	o.AttrRendered(a).Iterate(func(value engine.AttributeValue) bool {
		if hrm.RegExp.MatchString(value.String()) {
			result = true
			return false // break
		}
		return true // next
	})
	return
}
func (hrm HasRegexpMatch) ToLDAPFilter(a string) string {
	return a + "=/" + hrm.RegExp.String() + "/"
}
func (hrm HasRegexpMatch) ToWhereClause(a string) string {
	return "REGEXP(" + a + ", " + hrm.RegExp.String() + ")"
}

type RecursiveDNmatcher struct {
	AO *engine.IndexedGraph
	DN string
}

func (rdn RecursiveDNmatcher) Evaluate(a engine.Attribute, o *engine.Node) bool {
	return recursiveDNmatchFunc(o, a, rdn.DN, 10, rdn.AO)
}
func (rdn RecursiveDNmatcher) ToLDAPFilter(a string) string {
	return a + ":recursiveDN:=" + rdn.DN
}
func (rdn RecursiveDNmatcher) ToWhereClause(a string) string {
	return "RECURSIVEDNMATCH(" + a + ", " + rdn.DN + ")"
}
func recursiveDNmatchFunc(o *engine.Node, a engine.Attribute, dn string, maxdepth int, ao *engine.IndexedGraph) (result bool) {
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
		if parent, found := ao.Find(activedirectory.DistinguishedName, engine.NV(value.String())); found {
			result = recursiveDNmatchFunc(parent, a, dn, maxdepth-1, ao)
			return false // break
		}
		return true // next
	})
	return
}

type EdgeQuery struct {
	Graph     *engine.IndexedGraph
	Target    NodeFilter
	Direction engine.EdgeDirection
	Edge      engine.Edge
}

func (p EdgeQuery) Evaluate(o *engine.Node) bool {
	var result bool
	p.Graph.Edges(o, p.Direction).Iterate(func(target *engine.Node, edge engine.EdgeBitmap) bool {
		if (p.Edge == engine.AnyEdgeType && !edge.IsBlank()) || edge.IsSet(p.Edge) {
			if p.Target == nil || p.Target.Evaluate(target) {
				result = true
				return false // return from loop
			}
		}
		return true
	})
	return result
}
func (p EdgeQuery) ToLDAPFilter() string {
	var result string
	if p.Direction == engine.Out {
		result += "out"
	} else {
		result += "in"
	}
	result += "=" + p.Edge.String()
	if p.Target != nil {
		result += "(" + p.Target.ToLDAPFilter() + ")"
	}
	return result
}
func (p EdgeQuery) ToWhereClause() string {
	var result string
	if p.Direction == engine.Out {
		result += "out"
	} else {
		result += "in"
	}
	result += "=" + p.Edge.String()
	if p.Target != nil {
		result += "(" + p.Target.ToWhereClause() + ")"
	}
	return result
}
