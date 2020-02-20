package main

import (
	"testing"

	"github.com/OWASP/Amass/v3/requests"
	"github.com/stretchr/testify/assert"
)

func TestAbs(t *testing.T) {

	res := requests.Output{
		Name:      "foobar.securecodebox.io",
		Domain:    "securecodebox.io",
		Addresses: nil,
		Tag:       "",
		Source:    "",
	}

	actualFinding := CreateFinding(&res)

	assert.Equal(t, "foobar.securecodebox.io", actualFinding.Name, "they should be equal")
	assert.Equal(t, "Found subdomain foobar.securecodebox.io", actualFinding.Description, "they should be equal")
	assert.Equal(t, "foobar.securecodebox.io", actualFinding.Location, "they should be equal")
	assert.Equal(t, "INFORMATIONAL", actualFinding.Severity, "they should be equal")
	assert.Equal(t, "Subdomain", actualFinding.Category, "they should be equal")
	assert.Equal(t, "NETWORK", actualFinding.OsiLayer, "they should be equal")
}
