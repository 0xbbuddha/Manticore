package objects

import (
	"fmt"
	"strconv"

	"github.com/TheManticoreProject/Manticore/network/ldap/ldap_attributes"
)

type Domain struct {
	// LdapSession is the LDAP session object
	LdapSession LdapSessionInterface
	// DistinguishedName is the distinguished name of the domain
	DistinguishedName string
	// NetBIOSName is the NetBIOS name of the domain
	NetBIOSName string
	// DNSName is the DNS name of the domain
	DNSName string
	// SID is the SID of the domain
	SID string
}

// IsDomainFunctionalityAtLeast checks if the domain's functionality level is at least the specified level.
//
// This function retrieves the domain object for the given domain name and queries the LDAP server
// to get the "msDS-Behavior-Version" attribute, which represents the domain's functionality level.
// It then compares this value with the provided functionality level.
//
// Parameters:
//   - domain (string): The name of the domain to check.
//   - functionalityLevel (int): The minimum functionality level to check against.
//
// Returns:
//   - bool: True if the domain's functionality level is at least the specified level, false otherwise.
//
// Example:
//
//	domain := &Domain{}
//	isAtLeast := domain.IsDomainAtLeast(ldap_attributes.DomainFunctionalityLevel(3))
//	if isAtLeast {
//	    fmt.Println("The domain's functionality level is at least 3")
//	} else {
//	    fmt.Println("The domain's functionality level is less than 3")
//	}
//
// Note:
//   - This function assumes that the Session struct has a valid connection object and that the GetDomain and QueryBaseObject methods
//     are implemented correctly.
//   - The function logs a warning if the "msDS-Behavior-Version" attribute cannot be parsed to an integer.
func (domain *Domain) IsDomainFunctionalityAtLeast(functionalityLevel ldap_attributes.DomainFunctionalityLevel) (bool, error) {
	var err error

	query := fmt.Sprintf("(distinguishedName=%s)", domain.DistinguishedName)
	attributes := []string{"msDS-Behavior-Version"}
	results, err := domain.LdapSession.QueryBaseObject(domain.DistinguishedName, query, attributes)
	if err != nil {
		return false, fmt.Errorf("error querying LDAP: %w", err)
	}

	if len(results) != 0 {
		domainFunctionalityLevel, err := strconv.Atoi(results[0].GetAttributeValue("msDS-Behavior-Version"))
		if err != nil {
			return false, err
		} else {
			if domainFunctionalityLevel >= int(functionalityLevel) {
				return true, nil
			} else {
				return false, nil
			}
		}
	} else {
		return false, nil
	}
}
