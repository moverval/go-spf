package spf

import (
	"net"

	"github.com/miekg/dns"
)

// Get an SPF Record as string from a domain
//
// Returns an error if no spf record is found or dns name couldn't be resolved
func LookupSPF(domain string, nameserver string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver)

	if err != nil {
		return "", err
	}

	for _, answer := range in.Answer {
		if answer, ok := answer.(*dns.TXT); ok {
			for _, record := range answer.Txt {
				if IsSPF(record) {
					return record, nil
				}
			}
		}
	}

	return "", ErrNotFound
}

// Returns first a record as net.IP
//
// Returns an error if dns name couldn't be resolved
func LookupARec(domain string, nameserver string) (net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver)

	if err != nil {
		return nil, err
	}

	for _, answer := range in.Answer {
		if answer, ok := answer.(*dns.A); ok {
			return answer.A, nil
		}
	}

	return nil, nil
}

// Checks if ip is contained in a record
//
// Returns an error if dns name couldn't be resolved
func MatchIPWithARec(ip net.IP, domain string, nameserver string) (bool, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver)

	if err != nil {
		return false, err
	}

	for _, answer := range in.Answer {
		if answer, ok := answer.(*dns.A); ok {
			if ip.Equal(answer.A) {
				return true, nil
			}
		}
	}

	return false, nil
}

// Checks if ip is found in a record which was referenced by mx record
//
// Returns an error if dns name couldn't be resolved
func MatchIPWithMXRec(ip net.IP, domain string, nameserver string) (bool, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver)

	if err != nil {
		return false, err
	}

	for _, answer := range in.Answer {
		if answer, ok := answer.(*dns.MX); ok {
			match, err := MatchIPWithARec(ip, answer.Mx, nameserver)

			if err != nil {
				return false, err
			}

			return match, nil
		}
	}

	return false, nil
}

// Checks if ip resolves to domain name of variable domain
//
// Returns an error if dns name couldn't be resolved
func MatchIPWithPtrRec(ip net.IP, domain string, nameserver string) (bool, error) {
	m := new(dns.Msg)
	m.SetQuestion(ip.String(), dns.TypePTR)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver)

	if err != nil {
		return false, err
	}

	for _, answer := range in.Answer {
		if answer, ok := answer.(*dns.PTR); ok {
			if answer.Ptr == domain {
				return true, nil
			}
		}
	}

	return false, nil
}
