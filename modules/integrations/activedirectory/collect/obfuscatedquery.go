package collect

import "math/rand/v2"

var (
	alwaysHasDataAttributes = []string{
		"instanceType",
		"nTSecurityDescriptor",
		"objectCategory",
		"objectClass",
	}
	knownTimestampSecurityAttributes = []string{
		"whenCreated",
		"whenChanged",
	}
	knownTextAttributes = []string{
		"cn",
		"sn",
		"givenName",
		"displayName",
		"mail",
		"telephoneNumber",
		"title",
		"description",
		"department",
		"company",
		"manager",
		"employeeID",
		"employeeType",
		"physicalDeliveryOfficeName",
		"postalAddress",
		"homePhone",
		"mobile",
		"pager",
		"facsimileTelephoneNumber",
		"info",
		"url",
		"jpegPhoto",
		"userPrincipalName",
		"sAMAccountName",
		"objectGUID",
		"objectSid",
		"whenCreated",
		"whenChanged",
		"pwdLastSet",
		"logonCount",
		"badPwdCount",
		"accountExpires",
		"lockoutTime",
		"userAccountControl",
		"msDS-QuotaUsed",
		"msDS-QuotaEffective",
	}
	knownTimestampAttributes = []string{
		"whenCreated",
		"whenChanged",
		"pwdLastSet",
		"logonCount",
		"badPwdCount",
		"accountExpires",
		"lockoutTime",
	}
)

func generateObfuscatedQuery() string {
	return "(instanceType:1.2.840.113556.1.4.804:=63)"
}

func randomItemFromSlice(slice []string) string {
	if len(slice) == 0 {
		return ""
	}
	return slice[rand.IntN(len(slice))]
}
