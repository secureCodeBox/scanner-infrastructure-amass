package main

import (
	"fmt"
	"github.com/caffix/amass/amass"
	"github.com/nu7hatch/gouuid"
	"github.com/op/go-logging"
	"github.com/secureCodeBox/scanner-infrastructure-amass/ScannerScaffolding"
	"math/rand"
	"net"
	"os"
	"time"
)

var log = logging.MustGetLogger("SubdomainScanner")

type Address struct {
	Address     net.IP     `json:"ADDRESS"`
	Netblock    *net.IPNet `json:"NETBLOCK"`
	ASN         int        `json:"ASN"`
	Description string     `json:"DESCRIPTION"`
}

func createJobFailure(jobId string) ScannerScaffolding.JobFailure {
	return ScannerScaffolding.JobFailure{
		JobId:        jobId,
		ErrorMessage: "GoScanner Failed.",
		ErrorDetails: "",
	}
}

func workOnJobs(jobs <-chan ScannerScaffolding.ScanJob, results chan<- ScannerScaffolding.JobResult, failures chan<- ScannerScaffolding.JobFailure) {
	for job := range jobs {
		log.Infof("Working on job'%s'", job.JobId)

		output := make(chan *amass.AmassOutput)

		// Seed the default pseudo-random number generator
		rand.Seed(time.Now().UTC().UnixNano())

		// Setup the most basic amass configuration
		config := amass.CustomConfig(&amass.AmassConfig{Output: output})

		for _, target := range job.Targets {
			log.Infof("Job '%s' is scanning subdomains for '%s'", job.JobId, target.Location)
			config.AddDomains([]string{target.Location})
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

func main() {
	loggingBackend := logging.NewLogBackend(os.Stdout, "", 0)
	leveledBackend := logging.AddModuleLevel(loggingBackend)
	if os.Getenv("DEBUG") != "" {
		leveledBackend.SetLevel(logging.DEBUG, "")
	} else {
		leveledBackend.SetLevel(logging.INFO, "")
	}
	logging.SetBackend(leveledBackend)

	scanner := ScannerScaffolding.CreateJobConnection(
		"http://localhost:8080",
		"subdomain_scan",
		"SubdomainScanner",
	)

	block := make(chan bool)

	go workOnJobs(scanner.Jobs, scanner.Results, scanner.Failures)

	<-block
}
