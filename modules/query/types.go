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

type Query interface {
	Evaluate(o *engine.Object) bool
	ToLDAPFilter() string
	ToWhereClause() string
}

// Wraps one Attribute around a queryattribute interface
type QueryOneAttribute struct {
	a engine.Attribute
	q QueryAttribute
}

func (qoa QueryOneAttribute) Evaluate(o *engine.Object) bool {
	return qoa.q.Evaluate(qoa.a, o)
}

func (qoa QueryOneAttribute) ToLDAPFilter() string {
	return qoa.q.ToLDAPFilter(qoa.a.String())
}

func (qoa QueryOneAttribute) ToWhereClause() string {
	return qoa.q.ToWhereClause(qoa.a.String())
}

// Wraps one Attribute around a queryattribute interface
type QueryMultipleAttributes struct {
	attrglobstr string
	a           []engine.Attribute
	q           QueryAttribute
}

func (qma QueryMultipleAttributes) Evaluate(o *engine.Object) bool {
	for _, a := range qma.a {
		if qma.q.Evaluate(a, o) {
			return true
		}
	}
	return false
}

func (qma QueryMultipleAttributes) ToLDAPFilter() string {
	return qma.q.ToLDAPFilter(qma.attrglobstr)
}

func (qma QueryMultipleAttributes) ToWhereClause() string {
	return qma.q.ToWhereClause(qma.attrglobstr)
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

func (qaa QueryAnyAttribute) ToLDAPFilter() string {
	return "*" + qaa.q.ToLDAPFilter("*")
}

func (qaa QueryAnyAttribute) ToWhereClause() string {
	return "*" + qaa.q.ToWhereClause("*")
}

type QueryAttribute interface {
	Evaluate(a engine.Attribute, o *engine.Object) bool
	ToLDAPFilter(a string) string
	ToWhereClause(a string) string
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
	for i, s := range l {
		l[i] = strings.ToLower(s)
	}
	return l
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

type notquery struct {
	subitem Query
}

func (q notquery) Evaluate(o *engine.Object) bool {
	return !q.subitem.Evaluate(o)
}

func (q notquery) ToLDAPFilter() string {
	return "!(" + q.subitem.ToLDAPFilter() + ")"
}

func (q notquery) ToWhereClause() string {
	return "UNSUPPORTED!!"
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

func (cm countModifier) ToLDAPFilter(a string) string {
	return a + ":count: " + cm.c.String() + " " + strconv.FormatInt(cm.value, 10)
}

func (cm countModifier) ToWhereClause(a string) string {
	return "COUNT(" + a + ")" + cm.c.String() + " " + strconv.FormatInt(cm.value, 10)
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

func (lm lengthModifier) ToLDAPFilter(a string) string {
	return a + ":length: " + lm.c.String() + " " + strconv.FormatInt(lm.value, 10)
}

func (lm lengthModifier) ToWhereClause(a string) string {
	return "LENGTH(" + a + ")" + lm.c.String() + " " + strconv.FormatInt(lm.value, 10)
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

		if sm.c.Compare(t.Unix(), sm.ts.From(time.Now()).Unix()) {
			return true
		}
	}
	return false
}

func (sm sinceModifier) ToLDAPFilter(a string) string {
	return a + ":since: " + sm.c.String() + " " + sm.ts.String()
}

func (sm sinceModifier) ToWhereClause(a string) string {
	return "SINCE(" + a + ")" + sm.c.String() + " " + sm.ts.String()
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

func (td timediffModifier) ToLDAPFilter(a string) string {
	return a + ":timediff(" + td.a2.String() + "): " + td.c.String() + td.ts.String()
}

func (td timediffModifier) ToWhereClause(a string) string {
	return "TIMEIDFF(" + a + "," + td.a2.String() + ")" + td.c.String() + td.ts.String()
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

func (am andModifier) ToLDAPFilter(a string) string {
	return a + ":and:=" + strconv.FormatInt(am.value, 10)
}

func (am andModifier) ToWhereClause(a string) string {
	return a + " && " + strconv.FormatInt(am.value, 10) + "=" + strconv.FormatInt(am.value, 10)
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

func (om orModifier) ToLDAPFilter(a string) string {
	return a + ":or:=" + strconv.FormatInt(om.value, 10)
}

func (om orModifier) ToWhereClause(a string) string {
	return a + " || " + strconv.FormatInt(om.value, 10) + "=" + strconv.FormatInt(om.value, 10)
}

type numericComparator struct {
	c     comparatortype
	value int64
}

func (nc numericComparator) Evaluate(a engine.Attribute, o *engine.Object) bool {
	val, _ := o.AttrInt(a)
	return nc.c.Compare(val, nc.value)
}

func (nc numericComparator) ToLDAPFilter(a string) string {
	return a + nc.c.String() + strconv.FormatInt(nc.value, 10)
}

func (nc numericComparator) ToWhereClause(a string) string {
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

func (hgm hasGlobMatch) ToLDAPFilter(a string) string {
	return a + ":glob:=" + hgm.globstr
}

func (hgm hasGlobMatch) ToWhereClause(a string) string {
	return "GLOB(" + a + "," + hgm.globstr + ")"
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
	method engine.Edge
	target Query
}

func (p pwnquery) Evaluate(o *engine.Object) bool {
	items := o.CanPwn
	if !p.canpwn {
		items = o.PwnableBy
	}
	for pwntarget, pwnmethod := range items {
		if (p.method == engine.AnyEdgeType && pwnmethod.Count() != 0) || pwnmethod.IsSet(p.method) {
			if p.target == nil || p.target.Evaluate(pwntarget) {
				return true
			}
		}
	}
	return false
}

func (p pwnquery) ToLDAPFilter() string {
	var result string
	if p.canpwn {
		result += "_canpwn"
	} else {
		result += "_pwnable"
	}
	result += "=" + p.method.String()
	if p.target != nil {
		result += "(" + p.target.ToLDAPFilter() + ")"
	}
	return result
}

func (p pwnquery) ToWhereClause() string {
	var result string
	if p.canpwn {
		result += "_canpwn"
	} else {
		result += "_pwnable"
	}
	result += "=" + p.method.String()
	if p.target != nil {
		result += "(" + p.target.ToWhereClause() + ")"
	}
	return result
}
