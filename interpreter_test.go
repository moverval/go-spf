package spf_test

import (
	"net"
	"testing"

	"github.com/moverval/go-spf"
)

func TestValidationPass(t *testing.T) {
	// Check if google mail server can send mail from gmail.com
	result, err := spf.ValidateIP(net.ParseIP("35.190.247.10"), "gmail.com", "8.8.8.8:53", 10)

	if err != nil {
		t.Error(err)
		return
	}

	if result != spf.PassQualifier {
		t.Errorf("False Qualifier. Expected %q, got %q", spf.PassQualifier, result)
	}
}

func TestInclude(t *testing.T) {
	result, err := spf.ValidateIP(net.ParseIP("127.0.0.1"), "nsa.gov", "8.8.8.8:53", 10)

	if err != nil {
		t.Error(err)
		return
	}

	if result != spf.SoftFailQualifier {
		t.Errorf("False Qualifier. Expected %q, got %q", spf.SoftFailQualifier, result)
	}
}

func TestIp6(t *testing.T) {
	result, err := spf.ValidateIP(net.ParseIP("::1"), "nsa.gov", "8.8.8.8:53", 10)

	if err != nil {
		t.Error(err)
		return
	}

	if result != spf.SoftFailQualifier {
		t.Errorf("False Qualifier. Expected %q, got %q", spf.SoftFailQualifier, result)
	}
}

func TestValidationSoftFail(t *testing.T) {
	// Check if local ip can send mail as gmail.com
	result, err := spf.ValidateIP(net.ParseIP("192.168.178.50"), "gmail.com", "8.8.8.8:53", 10)

	if err != nil {
		t.Error(err)
		return
	}

	if result != spf.SoftFailQualifier {
		t.Errorf("False Qualifier. Expected %q, got %q", spf.SoftFailQualifier, result)
	}
}
