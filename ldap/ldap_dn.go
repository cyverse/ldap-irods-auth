package ldap

import "strings"

// GetUsernameFromDN returns username from dn
func GetUsernameFromDN(dn string) string {
	dnMap := ParseDN(dn)
	return dnMap["uid"]
}

// ParseDN parses dn into map
func ParseDN(dn string) map[string]string {
	fieldMap := map[string]string{}
	fields := strings.Split(dn, ",")
	for _, field := range fields {
		kv := strings.Split(field, "=")
		if len(kv) == 2 {
			k := strings.TrimSpace(kv[0])
			v := strings.TrimSpace(kv[1])
			fieldMap[k] = v
		}
	}
	return fieldMap
}

// CheckDNFilter checks if dn satisfies filter
func CheckDNFilter(filter string, dn string) bool {
	filterString := strings.Trim(filter, "()")

	if filterString == "objectclass=*" {
		// default match
		return true
	}

	return ValidateDN(filterString, dn)
}

// ValidateDN validates if dn is based on baseDN
func ValidateDN(baseDN string, dn string) bool {
	baseDnMap := ParseDN(baseDN)
	dnMap := ParseDN(dn)

	for k, v := range baseDnMap {
		// these must be in dn
		if v2, ok := dnMap[k]; ok {
			if v != v2 {
				return false
			}
		} else {
			return false
		}
	}
	return true
}
