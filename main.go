package main

import (
	"fmt"
	"github.com/OWASP/Amass/amass"
	"github.com/nu7hatch/gouuid"
	"github.com/op/go-logging"
	"github.com/secureCodeBox/scanner-infrastructure-amass/ScannerScaffolding"
	"math/rand"
	"net"
	"time"
)

var log = logging.MustGetLogger("SubdomainScanner")

type Address struct {
	Address     net.IP     `json:"ADDRESS"`
	Netblock    *net.IPNet `json:"NETBLOCK"`
	ASN         int        `json:"ASN"`
	Description string     `json:"DESCRIPTION"`
}

func createJobFailure(jobId, message, details string) ScannerScaffolding.JobFailure {
	return ScannerScaffolding.JobFailure{
		JobId:        jobId,
		ErrorMessage: message,
		ErrorDetails: details,
	}
}

func workOnJobs(jobs <-chan ScannerScaffolding.ScanJob, results chan<- ScannerScaffolding.JobResult, failures chan<- ScannerScaffolding.JobFailure) {
	for job := range jobs {
		log.Infof("Working on job '%s'", job.JobId)

		output := make(chan *amass.AmassOutput)

		// Seed the default pseudo-random number generator
		rand.Seed(time.Now().UTC().UnixNano())

		// Setup the most basic amass configuration
		config := amass.CustomConfig(&amass.AmassConfig{
			Output: output,
			NoDNS:  true,
		})

		for _, target := range job.Targets {
			log.Infof("Job '%s' is scanning subdomains for '%s'", job.JobId, target.Location)
			config.AddDomain(target.Location)

			if _, exists := target.Attributes["NO_DNS"]; exists == false {
				config.NoDNS = false
			} else {
				switch noDNS := target.Attributes["NO_DNS"].(type) {
				case bool:
					config.NoDNS = noDNS
				default:
					failures <- createJobFailure(job.JobId, "Scan Parameter 'NO_DNS' must be boolean", "")
				}
			}
		}

		findings := make([]ScannerScaffolding.Finding, 0)

		go func() {
			for {
				log.Debug("Waiting for new subdomains.")
				select {
				case result, more := <-output:
					if more == false {
						return
					}

					log.Debugf("Found new subdomain '%s'", result.Name)
					u, err := uuid.NewV4()
					if err != nil {
						log.Errorf("Could not create UUID for subdomain finding '%s'.", result.Domain)
						failures <- createJobFailure(job.JobId, "Could not create UUID for finding", "")
						return
					}

					addresses := make([]Address, 0)
					for _, address := range result.Addresses {
						addresses = append(addresses, Address{
							Address:     address.Address,
							Description: address.Description,
							Netblock:    address.Netblock,
							ASN:         address.ASN,
						})
					}

					attributes := make(map[string]interface{})

					attributes["Tag"] = result.Tag
					attributes["Type"] = result.Type
					attributes["SOURCE"] = result.Source
					attributes["DOMAIN"] = result.Domain
					attributes["ADDRESSES"] = addresses

					finding := ScannerScaffolding.Finding{
						Id:          u.String(),
						Name:        result.Name,
						Description: fmt.Sprintf("Found subdomain %s", result.Name),
						Location:    fmt.Sprintf("tcp://%s", result.Name),
						Category:    "Subdomain",
						Severity:    "INFORMATIONAL",
						OsiLayer:    "NETWORK",
						Attributes:  attributes,
					}
					findings = append(findings, finding)
				case <-time.After(2 * time.Hour):
					log.Warningf("Scan for Job '%s' timed out!", job.JobId)
					failures <- createJobFailure(job.JobId, "Subdomain Scan Timed out", "Subdomainscans are limited to a two hour timeframe")
					return
				}
			}
		}()

		// Begin the enumeration process
		amass.StartEnumeration(config)

		log.Infof("Subdomainscan '%s' found %d subdomains.", job.JobId, len(findings))

		results <- ScannerScaffolding.JobResult{
			JobId:       job.JobId,
			Findings:    findings,
			RawFindings: "[]",
		}
	}
}

func testScannerFunctionality() ScannerScaffolding.TestRun {
	return ScannerScaffolding.TestRun{
		Version:    "", //amass.Version,
		Details:    amass.Version,
		Successful: true,
	}
}

func main() {
	scanner := ScannerScaffolding.CreateJobConnection(
		ScannerScaffolding.ScannerConfiguration{
			EngineUrl:                "http://localhost:8080",
			TaskName:                 "subdomain_scan",
			ScannerType:              "SubdomainScanner",
			TestScannerFunctionality: testScannerFunctionality,
		},
	)

	workOnJobs(scanner.Jobs, scanner.Results, scanner.Failures)
}
