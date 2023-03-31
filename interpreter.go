package spf

import (
	"net"
	"strings"
)

// Returns the qualifier of a domain for given IP
//
// ValidateIP can check number of recursions subrecords until it gives up.
// To check infinitely, use a negative value
func ValidateIP(ip net.IP, name string, nameserver string, depth int) (Qualifier, error) {
	spf, err := LookupSPF(name, nameserver)

	if err != nil {
		return 0, err
	}

	record, err := ParseSPF(spf)

	if err != nil {
		return NoneQualifier, err
	}

	for _, mechanism := range record {
		qualifier, err := ExecuteMechanism(ip, mechanism, nameserver, depth)

		if err != nil {
			return NoneQualifier, err
		}

		if qualifier != NoneQualifier {
			return qualifier, nil
		}
	}

	return NoneQualifier, nil
}

// Make exact queries or execute a part of a record. This is used by ValidateIP
func ExecuteMechanism(ip net.IP, mechanism Mechanism, nameserver string, depth int) (Qualifier, error) {
	switch mechanism.Mechanism {
	case AllMechanism:
		return mechanism.Qualifier, nil
	case IPv4Mechanism, IPv6Mechanism:
		// Small and simple mechanism (fast to check)
		match, err := MatchIPWithCIDR(ip, mechanism.Value)

		if err != nil {
			return NoneQualifier, err
		}

		if !match {
			return NoneQualifier, nil
		}

		return mechanism.Qualifier, nil

	case AMechanism:
		// Good alternative to ip mechanisms
		match, err := MatchIPWithARec(ip, mechanism.Value, nameserver)

		if err != nil {
			return NoneQualifier, err
		}

		if !match {
			return NoneQualifier, nil
		}

		return mechanism.Qualifier, nil
	case MXMechanism:
		// Can have a lot of lookups :/
		match, err := MatchIPWithMXRec(ip, mechanism.Value, nameserver)

		if err != nil {
			return NoneQualifier, err
		}

		if !match {
			return NoneQualifier, nil
		}

		return mechanism.Qualifier, nil
	case PTRMechanism:
		// Can be time hungry :/
		match, err := MatchIPWithPtrRec(ip, mechanism.Value, nameserver)

		if err != nil {
			return NoneQualifier, err
		}

		if !match {
			return NoneQualifier, nil
		}

		return mechanism.Qualifier, nil
	case ExistsMechanism:
		// Complex mechanism (like if statement)
		query := strings.Replace(mechanism.Value, "%{i}", ip.String(), -1)

		resolved, err := LookupARec(query, nameserver)

		if err != nil {
			return NoneQualifier, err
		}

		if resolved == nil {
			return NoneQualifier, nil
		}

		return mechanism.Qualifier, nil
	case IncludeMechanism, RedirectMechanism:
		// Redirect and include behave the same when executed
		if depth == 0 {
			return NoneQualifier, ErrOutOfRecursions
		}

		spf, err := LookupSPF(mechanism.Value, nameserver)

		if err != nil {
			return NoneQualifier, err
		}

		parsedSpf, err := ParseSPF(spf)

		if err != nil {
			return NoneQualifier, err
		}

		for _, mechanism := range parsedSpf {
			result, err := ExecuteMechanism(ip, mechanism, nameserver, depth-1)

			if err != nil {
				return NoneQualifier, err
			}

			if result != NoneQualifier {
				// If e.g. -include was found, blacklist every ip from included spf record
				if mechanism.Qualifier != PassQualifier {
					return mechanism.Qualifier, nil
				}

				return result, nil
			}
		}

		return NoneQualifier, nil
	}

	return NoneQualifier, nil
}

// Check if ip exists in a network
//
// Returns an error if cidr is invalid
func MatchIPWithCIDR(ip net.IP, cidr string) (bool, error) {
	_, ipNet, err := net.ParseCIDR(cidr)

	if err != nil {
		return false, err
	}

	return ipNet.Contains(ip), nil
}
