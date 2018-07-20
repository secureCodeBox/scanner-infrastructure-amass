package ScannerScaffolding

import (
	"bytes"
	"encoding/json"
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

	StartedAt      time.Time
	InitialTestRun TestRun
	TaskStatus     *TaskStatus
	EngineStatus   *EngineStatus
}

type TestRun struct {
	Version    string `json:"version"`             // Version of Scanner
	Details    string `json:"test_run_details"`    // Description of the Test run. How was it performed?
	Successful bool   `json:"test_run_successful"` // Was the test run successful?
}

type ScannerConfiguration struct {
	EngineUrl                string
	TaskName                 string
	ScannerType              string
	TestScannerFunctionality func() TestRun
}

type TaskStatus struct {
	Started   int `json:"started"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

type EngineStatus struct {
	LastSuccessfulConnection      time.Time `json:"last_successful_connection"`
	HadSuccessfulEngineConnection bool      `json:"had_successful_connection"`
}

type BuildConfiguration struct {
	CommitId      string `json:"commit_id"`
	RepositoryUrl string `json:"repository_url"`
	Branch        string `json:"branch"`
}

type ScannerStatus struct {
	StartedAt          time.Time          `json:"started_at"`
	WorkerId           string             `json:"worker_id"`
	Healthcheck        string             `json:"healthcheck"`
	TaskStatus         TaskStatus         `json:"status"`
	EngineStatus       EngineStatus       `json:"engine"`
	ScannerStatus      TestRun            `json:"scanner"`
	BuildConfiguration BuildConfiguration `json:"build"`
}

func env(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if exists {
		return value
	}
	return defaultValue
}

func (scanner ScannerScaffolding) fetchJob() *ScanJob {
	res, err := http.Post(
		scanner.EngineUrl+"/box/jobs/lock/"+scanner.TaskName+"/"+scanner.ScannerId,
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
		scanner.logSuccessfulEngineConnection()
		return nil
	case "400":
		log.Warning("Invalid Response / Request to engine while fetching a new job.")
		return nil
	case "500":
		log.Warning("Encountered 500 Response Code from Engine while fetching a new job.")
		return nil
	}

	scanner.logSuccessfulEngineConnection()

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

	scanner.TaskStatus.Started = scanner.TaskStatus.Started + 1

	return &scanJob
}

func (scanner ScannerScaffolding) pullJobs() {
	for {
		scanJob := scanner.fetchJob()

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

		scanner.sendResults(
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

func (scanner ScannerScaffolding) sendResults(jobId string, result Result) {
	jsonBytes, err := json.Marshal(result)

	if err != nil {
		log.Criticalf("Failed to encode scan result of job '%s' as json", jobId)
	}

	res, err := http.Post(
		scanner.EngineUrl+"/box/jobs/"+jobId+"/result",
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
		scanner.TaskStatus.Completed++
		scanner.logSuccessfulEngineConnection()
	case "400":
		log.Warningf("Invalid Response / Request from engine while submitting result for job '%s'", jobId)
		scanner.TaskStatus.Failed++
	case "500":
		log.Warningf("Encountered 500 Response Code from Engine while submitting result for job '%s'", jobId)
		scanner.TaskStatus.Failed++
	default:
		log.Errorf("Got an unexpected response code ('%s') from engine while submitting result.", status)
		scanner.TaskStatus.Failed++
	}
}

func (scanner ScannerScaffolding) sendFailure(failure JobFailure) {
	scanner.TaskStatus.Failed++

	errorPayload := ScanError{
		ScannerId:    scanner.ScannerId,
		ErrorMessage: failure.ErrorMessage,
		ErrorDetails: failure.ErrorDetails,
	}

	jsonBytes, err := json.Marshal(errorPayload)

	if err != nil {
		log.Criticalf("Failed to encode error object of job '%s' as json", failure.JobId)
	}
	res, err := http.Post(
		scanner.EngineUrl+"/box/jobs/"+failure.JobId+"/failure",
		"application/json",
		bytes.NewBuffer(jsonBytes),
	)

	if err != nil {
		log.Errorf("Failed to send request for failure of job '%s'", failure.JobId)
	}

	status := strings.Trim(res.Status, " ")

	switch status {
	case "200":
		log.Infof("Successfully submitted failure report of job '%s'", failure.JobId)
		scanner.logSuccessfulEngineConnection()
	case "400":
		log.Warningf("Invalid Response / Request from engine while submitting failure report for job '%s'", failure.JobId)
	case "500":
		log.Warningf("Encountered 500 Response Code from Engine while submitting failure report for job '%s'", failure.JobId)
	default:
		log.Errorf("Got an unexpected response code ('%s') from engine while submitting failure report.", status)
	}
}

func (scanner ScannerScaffolding) submitFailures() {
	for failure := range scanner.Failures {
		log.Infof("Submitting failure for Job '%s'", failure.JobId)
		scanner.sendFailure(failure)
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

	log.Infof("Test Run Successful: %s\t", scanner.InitialTestRun.Successful)
	log.Infof("Test Run Details: %s\t", scanner.InitialTestRun.Details)
	log.Infof("Version: %s\t", scanner.InitialTestRun.Version)

	log.Info()
	log.Info("Build:")
	log.Infof("Commit: \t%s", env("SCB_COMMIT_ID", "unknown"))
	log.Infof("Repository: \t%s", env("SCB_REPOSITORY_URL", "unknown"))
	log.Infof("Branch: \t%s", env("SCB_BRANCH", "unknown"))
}

func (scanner ScannerScaffolding) logSuccessfulEngineConnection() {
	scanner.EngineStatus.LastSuccessfulConnection = time.Now()
	scanner.EngineStatus.HadSuccessfulEngineConnection = true
}

func (scanner ScannerScaffolding) healthyStatus() string {
	if scanner.isHealthy() {
		return "UP"
	} else {
		return "DOWN"
	}
}

func (scanner ScannerScaffolding) isHealthy() bool {
	return scanner.EngineStatus.HadSuccessfulEngineConnection && scanner.InitialTestRun.Successful
}

func (scanner ScannerScaffolding) generateScannerStatus() ScannerStatus {
	return ScannerStatus{
		StartedAt:     scanner.StartedAt,
		WorkerId:      scanner.ScannerId,
		Healthcheck:   scanner.healthyStatus(),
		TaskStatus:    *scanner.TaskStatus,
		EngineStatus:  *scanner.EngineStatus,
		ScannerStatus: scanner.InitialTestRun,
		BuildConfiguration: BuildConfiguration{
			CommitId:      env("SCB_COMMIT_ID", "unknown"),
			RepositoryUrl: env("SCB_REPOSITORY_URL", "unknown"),
			Branch:        env("SCB_BRANCH", "unknown"),
		},
	}
}

func statusPageHandler(scanner *ScannerScaffolding) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		if scanner.isHealthy() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}

		json.NewEncoder(w).Encode(scanner.generateScannerStatus())
	}
}

func (scanner *ScannerScaffolding) StartStatusServer() {
	http.HandleFunc("/status", statusPageHandler(scanner))
	http.ListenAndServe(":3003", nil)
}

func CreateJobConnection(configuration ScannerConfiguration) ScannerScaffolding {
	loggingBackend := logging.NewLogBackend(os.Stdout, "", 0)
	leveledBackend := logging.AddModuleLevel(loggingBackend)
	if os.Getenv("DEBUG") != "" {
		leveledBackend.SetLevel(logging.DEBUG, "")
	} else {
		leveledBackend.SetLevel(logging.INFO, "")
	}
	logging.SetBackend(leveledBackend)

	jobs := make(chan ScanJob)
	results := make(chan JobResult)
	failures := make(chan JobFailure)

	u, _ := uuid.NewV4()
	scannerId := u.String()

	scanner := ScannerScaffolding{
		ScannerId:      scannerId,
		ScannerType:    configuration.ScannerType,
		TaskName:       configuration.TaskName,
		EngineUrl:      env("ENGINE_ADDRESS", configuration.EngineUrl),
		Jobs:           jobs,
		Results:        results,
		Failures:       failures,
		InitialTestRun: configuration.TestScannerFunctionality(),
		StartedAt:      time.Now(),
		TaskStatus: &TaskStatus{
			Started:   0,
			Completed: 0,
			Failed:    0,
		},
		EngineStatus: &EngineStatus{
			LastSuccessfulConnection:      time.Unix(0, 0),
			HadSuccessfulEngineConnection: false,
		},
	}

	scanner.logConfiguration()

	go scanner.submitResults()
	go scanner.submitFailures()

	go scanner.pullJobs()
	go scanner.StartStatusServer()

	return scanner
}
