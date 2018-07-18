package ScannerScaffolding

import (
	"bytes"
	"encoding/json"
	"github.com/caffix/amass/amass"
	"github.com/nu7hatch/gouuid"
	"github.com/op/go-logging"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

type ScanJob struct {
	JobId   string   `json:"jobId"`
	Targets []Target `json:"targets"`
}

type JobResult struct {
	JobId       string
	Findings    []Finding
	RawFindings string
}

type JobFailure struct {
	JobId        string
	ErrorMessage string
	ErrorDetails string
}

type ScanError struct {
	ErrorMessage string `json:"errorMessage"`
	ErrorDetails string `json:"errorDetails"`
	ScannerId    string `json:"scannerId"`
}

type Target struct {
	Name       string                 `json:"name"`
	Location   string                 `json:"location"`
	Attributes map[string]interface{} `json:"attributes"`
}

type Result struct {
	Findings    []Finding `json:"findings"`
	RawFindings string    `json:"rawFindings"`
	ScannerId   string    `json:"scannerId"`
	ScannerType string    `json:"scannerType"`
}

type Finding struct {
	Id          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Location    string                 `json:"location"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	OsiLayer    string                 `json:"osi_layer"`
	Hint        string                 `json:"hint"`
	Reference   Reference              `json:"reference"`
	Attributes  map[string]interface{} `json:"attributes"`
}

type Reference struct {
	Id     string `json:"id"`
	Source string `json:"source"`
}

var log = logging.MustGetLogger("ScannerScaffolding")

type ScannerScaffolding struct {
	ScannerId   string
	ScannerType string
	TaskName    string

	EngineUrl string

	Jobs     chan ScanJob
	Results  chan JobResult
	Failures chan JobFailure
}

func env(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if exists {
		return value
	}
	return defaultValue
}

func fetchJob(scannerId, taskName string) *ScanJob {
	res, err := http.Post(
		"http://localhost:8080/box/jobs/lock/"+taskName+"/"+scannerId,
		"application/json",
		bytes.NewBuffer([]byte{}),
	)

	if err != nil {
		log.Warning("Failed to fetch job from engine.")
		log.Warning(err)
		return nil
	}

	status := strings.Trim(res.Status, " ")

	switch status {
	case "204":
		log.Debug("No jobs available. Going to sleep.")
		return nil
	case "400":
		log.Warning("Invalid Response / Request to engine while fetching a new job.")
	case "500":
		log.Warning("Encountered 500 Response Code from Engine while fetching a new job.")
	}

	body, err := ioutil.ReadAll(res.Body)

	if err != nil {
		log.Error("Failed to read response body stream.")
		return nil
	}

	scanJob := ScanJob{}

	err = json.Unmarshal(body, &scanJob)

	if err != nil {
		log.Error("Failed to parse json of a new job.")
		return nil
	}

	return &scanJob
}

func (scanner ScannerScaffolding) pullJobs() {
	for {
		scanJob := fetchJob(scanner.ScannerId, scanner.TaskName)

		if scanJob != nil {
			scanner.Jobs <- *scanJob
		}

		time.Sleep(time.Second)
	}
	close(scanner.Jobs)
}

func (scanner ScannerScaffolding) submitResults() {
	for result := range scanner.Results {
		log.Infof("Submitting result for Job '%s'\n", result.JobId)

		sendResults(
			result.JobId,
			Result{
				Findings:    result.Findings,
				RawFindings: result.RawFindings,
				ScannerId:   scanner.ScannerId,
				ScannerType: scanner.ScannerType,
			},
		)
	}
}

func sendResults(jobId string, result Result) {
	jsonBytes, err := json.Marshal(result)

	if err != nil {
		log.Criticalf("Failed to encode scan result of job '%s' as json", jobId)
	}

	res, err := http.Post(
		"http://localhost:8080/box/jobs/"+jobId+"/result",
		"application/json",
		bytes.NewBuffer(jsonBytes),
	)

	if err != nil {
		log.Errorf("Failed to send request for result of job '%s'", jobId)
	}

	status := strings.Trim(res.Status, " ")

	switch status {
	case "200":
		log.Infof("Successfully submitted result of job '%s'", jobId)
	case "400":
		log.Warningf("Invalid Response / Request from engine while submitting result for job '%s'", jobId)
	case "500":
		log.Warningf("Encountered 500 Response Code from Engine while submitting result for job '%s'", jobId)
	default:
		log.Errorf("Got an unexpected response code ('%s') from engine while submitting result.", status)
	}
}

func (scanner ScannerScaffolding) submitFailures() {
	for failure := range scanner.Failures {
		log.Criticalf("TODO: Submitting failure for Job '%s'", failure.JobId)
	}
}

func (scanner ScannerScaffolding) logConfiguration() {
	log.Info("Worker Settings:")

	log.Infof("Id: \t\t%s", scanner.ScannerId)
	log.Infof("TopicName: \t%s", scanner.TaskName)
	log.Infof("WorkerName: \t%s", scanner.ScannerType)
	log.Infof("EngineAddress: \t%s", scanner.EngineUrl)

	log.Info()
	log.Info("Scanner Status:")

	log.Info("Test Run: \t")
	log.Info("Version: \t", amass.Version)

	log.Info()
	log.Info("Build:")
	log.Infof("Commit: \t%s", env("SCB_COMMIT_ID", "unkown"))
	log.Infof("Repository: \t%s", env("SCB_REPOSITORY_URL", "unkown"))
	log.Infof("Branch: \t%s", env("SCB_BRANCH", "unkown"))
}

func CreateJobConnection(engineUrl, taskName, scannerType string) ScannerScaffolding {
	jobs := make(chan ScanJob)
	results := make(chan JobResult)
	failures := make(chan JobFailure)

	u, _ := uuid.NewV4()
	scannerId := u.String()

	scanner := ScannerScaffolding{
		ScannerId:   scannerId,
		ScannerType: scannerType,
		TaskName:    taskName,
		EngineUrl:   env("ENGINE_ADDRESS", engineUrl),
		Jobs:        jobs,
		Results:     results,
		Failures:    failures,
	}

	scanner.logConfiguration()

	go scanner.submitResults()
	go scanner.submitFailures()

	go scanner.pullJobs()

	return scanner
}
