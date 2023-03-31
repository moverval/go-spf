# Go-SPF

## TL;DR

This package provides easy to use features, to validate, if an IP belongs to a network.
It supports all `spf1` mechanisms and the redirect modifier.

To check if an ip belongs to network

```go
// ValidateIP(ip, domain, nameserver, follows)
result, err := spf.ValidateIP(net.ParseIP("35.190.247.10"), "gmail.com", "8.8.8.8:53", 3)

if err != nil {
    // handle error
}

switch result {
case spf.PassQualifier:
    // IP belongs to network
case spf.NeutralQualifier:
    // IP was found but no conclusion can be made
case spf.NoneQualifier:
    // No match was found for the ip. This should be treated as Neutral
case spf.SoftFailQualifier:
    // IP is probably not from the network
case spf.FailQualifier:
    // IP is not from the network
}
```