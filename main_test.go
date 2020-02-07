package main

import (
	"testing"

	"github.com/OWASP/Amass/v3/requests"
	"github.com/secureCodeBox/scanner-infrastructure-amass/ScannerScaffolding"
)

func TestAbs(t *testing.T) {

	res := requests.Output{
		Name:      "foobar.securecodebox.io",
		Domain:    "securecodebox.io",
		Addresses: nil,
		Tag:       "",
		Source:    "",
	}

	expectedFinding := ScannerScaffolding.Finding{
		Name:        "foobar.securecodebox.io",
		Description: "Found subdomain foobar.securecodebox.io",
		Location:    "foobar.securecodebox.io",
		Severity:    "INFORMATIONAL",
		Category:    "Subdomain",
		OsiLayer:    "NETWORK",
	}

	actualFinding := CreateFinding(&res)

	compareFindings(t, expectedFinding, actualFinding)
}

func compareFindings(t *testing.T, expectedFinding, actualFinding ScannerScaffolding.Finding) {
	if expectedFinding.Name != actualFinding.Name {
		t.Errorf("Expected Name to be '%s', was: '%s'", expectedFinding.Name, actualFinding.Name)
	}
	if expectedFinding.Description != actualFinding.Description {
		t.Errorf("Expected Description to be '%s', was: '%s'", expectedFinding.Description, actualFinding.Description)
	}
	if expectedFinding.Location != actualFinding.Location {
		t.Errorf("Expected Location to be '%s', was: '%s'", expectedFinding.Location, actualFinding.Location)
	}
	if expectedFinding.Severity != actualFinding.Severity {
		t.Errorf("Expected Severity to be '%s', was: '%s'", expectedFinding.Severity, actualFinding.Severity)
	}
	if expectedFinding.Category != actualFinding.Category {
		t.Errorf("Expected Category to be '%s', was: '%s'", expectedFinding.Category, actualFinding.Category)
	}
	if expectedFinding.OsiLayer != actualFinding.OsiLayer {
		t.Errorf("Expected OsiLayer to be '%s', was: '%s'", expectedFinding.OsiLayer, actualFinding.OsiLayer)
	}
}
