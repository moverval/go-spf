package spf_test

import (
	"testing"

	"github.com/moverval/go-spf"
)

func TestLookupSPF(t *testing.T) {
	record, err := spf.LookupSPF("gmail.com", "8.8.8.8:53")
	if err != nil {
		t.Errorf("No record found: %s", err)
	}

	if !spf.IsSPF(record) {
		t.Errorf("Value is not spf record")
	}
}
