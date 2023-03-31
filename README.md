# Go-SPF

## TL;DR

To add this package to your go imports, use

```bash
go get github.com/moverval/go-spf
```

---

This package provides easy to use features, to validate, if an IP belongs to a network.
It supports all `spf1` mechanisms and the redirect modifier.

To check if an ip belongs to a network

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

## Errors

All custom error types can be seen in `errors.go`. If an error get's thrown, it is most of the time the issuers fault, but errors can also occur if a dns record could not be resolved.

Examples of errors:

- Syntax

The spf record has an invalid syntax.

- OutOfRecursions

The issuer exceeded the `include` or `redirect` depth. (Use -1 to make the depth infinite; not recommended)

## Lookup SPF

SPF can also only be queried. If you only want the spf record string, use `LookupSPF`

```go
record, err := spf.LookupSPF("gmail.com", "8.8.8.8:53")

if err != nil {
    // handle error
}

// do something with the record
```

## Parse SPF

This library has a custom parser to evaluate spf strings. It handles strings gracefully and tries to interpret them correctly even if they are false.

```go
result, err := spf.ParseSPF("v=spf1 -include:ban.voulter.com include:spf.voulter.com include:spf2.voulter.com a:voulter.com ip4:127.0.0.1 ip6:::1 ~all")

var expected spf.Record = []spf.Mechanism{
    {Qualifier: spf.FailQualifier, Mechanism: spf.IncludeMechanism, Value: "ban.voulter.com"},
    {Qualifier: spf.PassQualifier, Mechanism: spf.IncludeMechanism, Value: "spf.voulter.com"},
    {Qualifier: spf.PassQualifier, Mechanism: spf.IncludeMechanism, Value: "spf2.voulter.com"},
    {Qualifier: spf.PassQualifier, Mechanism: spf.AMechanism, Value: "voulter.com"},
    {Qualifier: spf.PassQualifier, Mechanism: spf.IPv4Mechanism, Value: "127.0.0.1"},
    {Qualifier: spf.PassQualifier, Mechanism: spf.IPv6Mechanism, Value: "::1"},
    {Qualifier: spf.SoftFailQualifier, Mechanism: spf.AllMechanism, Value: ""},
}

if err != nil {
    // handle error
    // an error should not occur in this example
}

if reflect.DeepEqual(result, expected) {
    // this is true
}
```

## Advanced: Partial Parse SPF

Because Subcomponents are exposed by design, it is possible the evaluate individual Mechanisms seperately. For more information look at `interpreter.go/ExecuteMechanism`.