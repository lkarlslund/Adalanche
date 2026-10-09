package mcpserver

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
)

// Secrets are never returned, and nothing may be filtered or sorted by
// them, as matching values would tell them one guess at a time.

const redacted = "<redacted>"

// secretName reports whether an attribute's name says it holds a password,
// hash or key, for attributes nothing has declared.
func secretName(name string) bool {
	name = strings.ToLower(name)
	// Facts about secrets are not secrets.
	for _, about := range []string{"time", "count", "length", "age", "expir", "lastset", "properties", "policy", "quality"} {
		if strings.Contains(name, about) {
			return false
		}
	}
	for _, secret := range []string{"password", "pwd", "secret", "credential", "hash", "keypackage", "masterkey", "privatekey"} {
		if strings.Contains(name, secret) {
			return true
		}
	}
	return false
}

// secret reports whether values of an attribute must not be given out.
func secret(attr engine.Attribute) bool {
	if attr == engine.NonExistingAttribute {
		return false
	}
	if attr.HasFlag(engine.Secret) {
		return true
	}
	switch attr.AttributeType() {
	case engine.AttributeTypeInt, engine.AttributeTypeFloat, engine.AttributeTypeBool,
		engine.AttributeTypeTime, engine.AttributeTypeTime100NS:
		return false
	}
	return secretName(attr.String())
}

// secretByName is secret for an attribute named in a filter or option.
func secretByName(name string) bool {
	if attr := engine.LookupAttribute(name); attr != engine.NonExistingAttribute {
		return secret(attr)
	}
	return secretName(name)
}

// filterAttribute finds the attribute each comparison in an LDAP style
// filter tests: "(name=...)", "(name>=...)", "(name:rule:=...)".
var filterAttribute = regexp.MustCompile(`\(\s*([A-Za-z0-9_.*-]+)\s*(?::[^()=]*)?(?:=|>=|<=|~=)`)

// checkFilter refuses filters, or queries holding them, that test secret
// attributes or every attribute at once.
func checkFilter(filter string) error {
	for _, m := range filterAttribute.FindAllStringSubmatch(filter, -1) {
		name := m[1]
		if name == "*" {
			return fmt.Errorf("filters on every attribute (*=...) are not available here, as they would match secrets; name the attributes to test")
		}
		if secretByName(name) {
			return fmt.Errorf("attribute %q holds secrets and cannot be filtered on", name)
		}
	}
	return nil
}
