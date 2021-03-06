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

func createJobFailure(jobID, message, details string) ScannerScaffolding.JobFailure {
	return ScannerScaffolding.JobFailure{
		JobId:        jobID,
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
	attributes["SUBDOMAIN"] = amassResult.Name
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

// ErrorNoDNSConfig NoDNS needs to be of boolean value
var ErrorNoDNSConfig = errors.New("Scan Parameter 'NO_DNS' must be boolean")

func configureAmassScan(target ScannerScaffolding.Target, localSystem *services.LocalSystem) (*enum.Enumeration, error) {
	enumeration := enum.NewEnumeration(localSystem)
	if _, isDebug := os.LookupEnv("DEBUG"); isDebug {
		logger.Infof("Setting up high verbosity Logger for amass.")
		enumeration.Config.Log = log.New(os.Stdout, "amass", log.Ldate|log.Ltime|log.Lshortfile)
	}
	enumeration.Config.AddDomain(target.Location)
	if _, exists := target.Attributes["NO_DNS"]; exists == false {
		enumeration.Config.Passive = true
	} else {
		switch noDNS := target.Attributes["NO_DNS"].(type) {
		case bool:
			enumeration.Config.Passive = noDNS
		default:
			return nil, ErrorNoDNSConfig
		}
	}
	enumeration.Config.Dir = "/tmp"

	return enumeration, nil
}

func workOnJobs(jobs <-chan ScannerScaffolding.ScanJob, results chan<- ScannerScaffolding.JobResult, failures chan<- ScannerScaffolding.JobFailure) {
	localSystem, err := services.NewLocalSystem(config.NewConfig())
	if err != nil {
		panic("Failed to initialize local scan system")
	}
	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	for job := range jobs {
		logger.Infof("Working on job '%s'", job.JobId)

		findings := make([]ScannerScaffolding.Finding, 0)

		for _, target := range job.Targets {
			logger.Infof("Job '%s' is scanning subdomains for '%s'", job.JobId, target.Location)

			enumeration, err := configureAmassScan(target, localSystem)
			if errors.Is(err, ErrorNoDNSConfig) {
				failures <- createJobFailure(job.JobId, "Scan Parameter 'NO_DNS' must be boolean", "")
			} else if err != nil {
				failures <- createJobFailure(job.JobId, "Error while configuring scan", "")
			}

			// Begin the enumeration process
			if err := enumeration.Start(); err != nil {
				logger.Errorf("Could not start the amass scan.")
				logger.Error(err)
				failures <- createJobFailure(job.JobId, "Failed to start amass scan", err.Error())
			}

			logger.Debug("Started scan. Waiting for results to come in.")
			for result := range enumeration.Output {
				logger.Debugf("Found subdomain '%s'", result.Name)
				findings = append(findings, CreateFinding(result))
			}

			logger.Debugf("All scan results for '%s' are in. Waiting until amass marks itself as done.", target.Location)
			enumeration.Done()
		}

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
