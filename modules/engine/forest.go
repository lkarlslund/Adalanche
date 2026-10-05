package engine

import "strings"

// A forest's configuration partition, CN=Configuration,<forest root DN>,
// holds its schema, sites and directory settings, and a crossRef for each of
// its domains in CN=Partitions. Domain names do not tell the forest: a
// forest can hold several domain trees with unrelated names.

// crossRefNCName is the attribute a crossRef names its domain by.
var crossRefNCName = NewAttribute("nCName")

const partitionsInfix = ",cn=partitions,cn=configuration,"

// ForestRoot returns the lower-cased DN of the root domain of the forest a
// domain belongs to, read from the domain's crossRef, or "" when the data
// has no crossRef for it.
func ForestRoot(ao GraphReader, domainDN string) string {
	if domainDN == "" {
		return ""
	}
	crossRef, found := ao.FindTwo(ObjectClass, NV("crossRef"), crossRefNCName, NV(domainDN))
	if !found {
		return ""
	}
	if _, root, found := strings.Cut(strings.ToLower(crossRef.DN()), partitionsInfix); found {
		return root
	}
	return ""
}

// InForest reports whether a domain belongs to the forest whose root domain
// is root: as the domain's crossRef says when the data has it, otherwise
// when the domain's name ends with the root's.
func InForest(ao GraphReader, domainDN, root string) bool {
	if domainDN == "" || root == "" {
		return false
	}
	root = strings.ToLower(root)
	if forest := ForestRoot(ao, domainDN); forest != "" {
		return forest == root
	}
	domain := strings.ToLower(domainDN)
	return domain == root || strings.HasSuffix(domain, ","+root)
}
