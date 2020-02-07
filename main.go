package main

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
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

// CreateFinding creates a secureCodeBox Finding from an amass finding.
func CreateFinding(amassResult *requests.Output) ScannerScaffolding.Finding {
	u := uuid.Must(uuid.NewV4())

	addresses := make([]Address, 0)
	for _, address := range amassResult.Addresses {
		addresses = append(addresses, Address{
			Address:     address.Address,
			Description: address.Description,
			Netblock:    address.Netblock,
			ASN:         address.ASN,
		})
	}

	attributes := make(map[string]interface{})

	attributes["Tag"] = amassResult.Tag
	attributes["NAME"] = amassResult.Name
	attributes["SOURCE"] = amassResult.Source
	attributes["DOMAIN"] = amassResult.Domain
	attributes["ADDRESSES"] = addresses

	return ScannerScaffolding.Finding{
		Id:          u.String(),
		Name:        amassResult.Name,
		Description: fmt.Sprintf("Found subdomain %s", amassResult.Name),
		Location:    amassResult.Name,
		Category:    "Subdomain",
		Severity:    "INFORMATIONAL",
		OsiLayer:    "NETWORK",
		Attributes:  attributes,
	}
}

// converts amass output channel into finding list over time
func gatherFindingsFromAmass(amassResults <-chan *requests.Output) ([]ScannerScaffolding.Finding, error) {
	findings := make([]ScannerScaffolding.Finding, 0)

	for {
		logger.Debug("Waiting for new subdomains.")
		select {
		case result, more := <-amassResults:
			if more == false {
				return findings, nil
			}

			logger.Debugf("Found new subdomain '%s'", result.Name)

			findings = append(findings, CreateFinding(result))
		case <-time.After(2 * time.Hour):
			return nil, errors.New("Scan timed out")
		}
	}
}

// converts amass output channel into Scan Report / Job Result over time
func gatherMultipleAmassResultsIntoOneScanReport(jobID string, amassResults <-chan *requests.Output, results chan<- ScannerScaffolding.JobResult, failures chan<- ScannerScaffolding.JobFailure) {
	findings, err := gatherFindingsFromAmass(amassResults)
	logger.Infof("Subdomainscan '%s' found %d subdomains.", jobID, len(findings))

	if err != nil {
		logger.Warningf("Scan for Job '%s' timed out!", jobID)
		failures <- createJobFailure(jobID, "Subdomain Scan Timed out", "Subdomainscans are limited to a two hour timeframe")
	}

	results <- ScannerScaffolding.JobResult{
		JobId:       jobID,
		Findings:    findings,
		RawFindings: "[]",
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

		// Create a new channel onto which the results from all amass scans of this job get pushed
		masterOutput := make(chan *requests.Output)

		// Start separate goroutine to listen on the master output and convert and submit results back to the engine when done
		go gatherMultipleAmassResultsIntoOneScanReport(job.JobId, masterOutput, results, failures)

		for _, target := range job.Targets {
			// Configure amass scan
			enumeration := enum.NewEnumeration(sys)
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

			// Wait for scan to complete
			enumeration.Done()

			// Copy individual amass results over to master output channel
			for result := range enumeration.Output {
				masterOutput <- result
			}
		}
		close(masterOutput)
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
