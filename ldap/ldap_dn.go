package ldap

import (
	"strings"
)

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

func ParseDNFilter(filter string) (string, []string) {
	if filter[0] == '(' {
		filter = filter[1 : len(filter)-1]
	}

	// TODO: need to handle other operations
	filters := []string{}
	if filter[0] == '&' || filter[0] == '|' {
		// and
		filterStrings := strings.Split(filter[1:], ")(")
		for _, filterString := range filterStrings {
			filterString = strings.Trim(filterString, "()")
			filters = append(filters, filterString)
		}

		return "&", filters
	}

	filters = append(filters, filter)
	return "", filters
}

// ExtractFilterValue extracts filter value
func ExtractFilterValue(filter string, key string) string {
	_, filterStrings := ParseDNFilter(filter)
	for _, filterString := range filterStrings {
		kv := strings.Split(filterString, "=")
		if len(kv) == 2 && strings.TrimSpace(kv[0]) == key {
			return strings.TrimSpace(kv[1])
		}
	}
	return ""
}

// CheckDNFilter checks if dn satisfies filter
func CheckDNFilter(filter string, dn string) bool {
	_, filterStrings := ParseDNFilter(filter)
	for _, filterString := range filterStrings {
		if filterString == "objectclass=*" {
			// ignore
		} else {
			// key=val
			if !ValidateDN(filterString, dn) {
				return false
			}
		}
	}
	return true
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
