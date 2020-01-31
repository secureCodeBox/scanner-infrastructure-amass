package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/enum"
	"github.com/OWASP/Amass/v3/format"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/services"
	uuid "github.com/gofrs/uuid"
	"github.com/op/go-logging"
	"github.com/secureCodeBox/scanner-infrastructure-amass/ScannerScaffolding"
)

var logger = logging.MustGetLogger("SubdomainScanner")

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
	sys, err := services.NewLocalSystem(config.NewConfig())
	if err != nil {
		panic("Failed to initialize local scan system")
	}
	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	for job := range jobs {
		logger.Infof("Working on job '%s'", job.JobId)
		masterOutput := make(chan *requests.Output)

		findings := make([]ScannerScaffolding.Finding, 0)

		go func() {
			for {
				logger.Debug("Waiting for new subdomains.")
				select {
				case result, more := <-masterOutput:
					if more == false {
						return
					}

					logger.Debugf("Found new subdomain '%s'", result.Name)
					u := uuid.Must(uuid.NewV4())

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
					attributes["NAME"] = result.Name
					attributes["SOURCE"] = result.Source
					attributes["DOMAIN"] = result.Domain
					attributes["ADDRESSES"] = addresses

					finding := ScannerScaffolding.Finding{
						Id:          u.String(),
						Name:        result.Name,
						Description: fmt.Sprintf("Found subdomain %s", result.Name),
						Location:    result.Name,
						Category:    "Subdomain",
						Severity:    "INFORMATIONAL",
						OsiLayer:    "NETWORK",
						Attributes:  attributes,
					}
					findings = append(findings, finding)
				case <-time.After(2 * time.Hour):
					logger.Warningf("Scan for Job '%s' timed out!", job.JobId)
					failures <- createJobFailure(job.JobId, "Subdomain Scan Timed out", "Subdomainscans are limited to a two hour timeframe")
					return
				}
			}
		}()
		var wg sync.WaitGroup

		for _, target := range job.Targets {
			enumeration := enum.NewEnumeration(sys)

			wg.Add(1)
			go func() {
				defer wg.Done()
				for result := range enumeration.Output {
					masterOutput <- result
				}
			}()

			if _, isDebug := os.LookupEnv("DEBUG"); isDebug {
				logger.Infof("Setting up high verbosity Logger for amass.")
				enumeration.Config.Log = log.New(os.Stdout, "amass", log.Ldate|log.Ltime|log.Lshortfile)
			}

			logger.Infof("Job '%s' is scanning subdomains for '%s'", job.JobId, target.Location)

			enumeration.Config.AddDomain(target.Location)

			if _, exists := target.Attributes["NO_DNS"]; exists == false {
				enumeration.Config.Passive = true
			} else {
				switch noDNS := target.Attributes["NO_DNS"].(type) {
				case bool:
					enumeration.Config.Passive = noDNS
				default:
					failures <- createJobFailure(job.JobId, "Scan Parameter 'NO_DNS' must be boolean", "")
				}
			}

			enumeration.Config.Dir = "/tmp"

			// Begin the enumeration process
			if err := enumeration.Start(); err != nil {
				logger.Errorf("Could not start the amass scan.")
				logger.Error(err)
				failures <- createJobFailure(job.JobId, "Failed to start amass scan", err.Error())
			}
			enumeration.Done()

			wg.Wait()
			close(masterOutput)
		}

		logger.Infof("Subdomainscan '%s' found %d subdomains.", job.JobId, len(findings))

		results <- ScannerScaffolding.JobResult{
			JobId:       job.JobId,
			Findings:    findings,
			RawFindings: "[]",
		}
	}
}

func testScannerFunctionality() ScannerScaffolding.TestRun {
	return ScannerScaffolding.TestRun{
		Version:    format.Version,
		Details:    "Not feasible",
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
