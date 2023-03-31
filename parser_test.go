package spf_test

import (
	"reflect"
	"testing"

	"github.com/moverval/go-spf"
)

func TestParseSPFLong(t *testing.T) {
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
		t.Error(err)
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Not as expected: %q does not equal to %q", result, &expected)
	}
}

func TestParseInclude(t *testing.T) {
	result, err := spf.ParseSPF("v=spf1 include:spf.voulter.com")

	var expected spf.Record = []spf.Mechanism{
		{Qualifier: spf.PassQualifier, Mechanism: spf.IncludeMechanism, Value: "spf.voulter.com"},
	}

	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Not as expected: %q does not equal to %q", result, &expected)
	}
}

func TestParseHasMinus(t *testing.T) {
	result, err := spf.ParseSPF("v=spf1 include:spf-test.voulter.com")

	var expected spf.Record = []spf.Mechanism{
		{Qualifier: spf.PassQualifier, Mechanism: spf.IncludeMechanism, Value: "spf-test.voulter.com"},
	}

	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Not as expected: %q does not equal to %q", result, &expected)
	}
}

func TestParseUnformatted(t *testing.T) {
	result, err := spf.ParseSPF("v=spf1                  InCluDe:      spf.voulter.com     ")

	var expected spf.Record = []spf.Mechanism{
		{Qualifier: spf.PassQualifier, Mechanism: spf.IncludeMechanism, Value: "spf.voulter.com"},
	}

	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Not as expected: %q does not equal to %q", result, &expected)
	}
}

func TestParseFailInvalidMechanism(t *testing.T) {
	_, err := spf.ParseSPF("v=spf1 notinstandard: helloworld")

	if err == nil {
		t.Errorf("This test should output an error")
	}

	if err.Error() != "invalidmechanism" {
		t.Errorf("Error should output 'invalidmechanism', got '%s' instead", err.Error())
	}
}

func TestParseFailSyntax(t *testing.T) {
	_, err := spf.ParseSPF("v=spf1  : helloworld")

	if err == nil {
		t.Errorf("This test should output an error")
	}

	if err.Error() != "syntax" {
		t.Errorf("Error should output 'syntax', got '%s' instead", err.Error())
	}
}

func TestParseQualifiers(t *testing.T) {
	result, err := spf.ParseSPF("v=spf1 + ip4:127.0.0.1 - ip4:192.168.178.0 ~ip4:1.1.1.1 ?ip4:8.8.8.8")

	var expected spf.Record = []spf.Mechanism{
		{Qualifier: spf.PassQualifier, Mechanism: spf.IPv4Mechanism, Value: "127.0.0.1"},
		{Qualifier: spf.FailQualifier, Mechanism: spf.IPv4Mechanism, Value: "192.168.178.0"},
		{Qualifier: spf.SoftFailQualifier, Mechanism: spf.IPv4Mechanism, Value: "1.1.1.1"},
		{Qualifier: spf.NeutralQualifier, Mechanism: spf.IPv4Mechanism, Value: "8.8.8.8"},
	}

	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Not as expected: %q does not equal to %q", result, &expected)
	}
}

func TestRedirect(t *testing.T) {
	result, err := spf.ParseSPF("v=spf1 redirect=_spf.voulter.com")

	var expected spf.Record = []spf.Mechanism{
		{Qualifier: spf.PassQualifier, Mechanism: spf.RedirectMechanism, Value: "_spf.voulter.com"},
	}

	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Not as expected: %q does not equal to %q", result, &expected)
	}
}

func TestRedirectWithMechanisms(t *testing.T) {
	result, err := spf.ParseSPF("v=spf1 redirect=_spf.voulter.com + a:127.0.0.1 - a:192.168.178.0 ~a:1.1.1.1 ?a:8.8.8.8")

	var expected spf.Record = []spf.Mechanism{
		{Qualifier: spf.PassQualifier, Mechanism: spf.AMechanism, Value: "127.0.0.1"},
		{Qualifier: spf.FailQualifier, Mechanism: spf.AMechanism, Value: "192.168.178.0"},
		{Qualifier: spf.SoftFailQualifier, Mechanism: spf.AMechanism, Value: "1.1.1.1"},
		{Qualifier: spf.NeutralQualifier, Mechanism: spf.AMechanism, Value: "8.8.8.8"},
		{Qualifier: spf.PassQualifier, Mechanism: spf.RedirectMechanism, Value: "_spf.voulter.com"},
	}

	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Not as expected: %q does not equal to %q", result, &expected)
	}
}
