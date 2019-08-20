package p

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"unicode"

	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
)

const (
	ghStatusSuccess = "success"
	ghStatusFailure = "failure"
)

type validator struct {
	PullRequest pullRequest `json:"pull_request"`
	Token       string
}

type pullRequest struct {
	Head  head
	Title string
	Body  string
}

type head struct {
	Sha string
}

func newValidator(body io.ReadCloser) (*validator, error) {
	var v validator
	if err := json.NewDecoder(body).Decode(&v); err != nil {
		return nil, fmt.Errorf("failed to decode requestBody: %v", err)
	}
	token, err := getGitHubToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get GitHub token: %v", err)
	}
	v.Token = token
	return &v, nil
}

var encryptedToken = "CiQA0ev1XO7mUrSoJWceUh6kXkEeExjdebXlIQ9maVLlD6BztVISUQB15DKow2f15qU1QLIETYzK9/rftpgFLIwXdpq6R8pW3IrrQr3Tpl4vCr6zRyMRNam6zeWd8QmTpkd2RVf2Brg5qsX+RJymqGJwndTt1quDjw=="
var kmsKey = "projects/gcp-test-195721/locations/global/keyRings/test/cryptoKeys/github_access_test_key"

// ReportPRValidationStatus check whether PR title and description is valid and report status to GitHub.
func ReportPRValidationStatus(w http.ResponseWriter, r *http.Request) {
	v, err := newValidator(r.Body)
	if err != nil {
		log.Printf("Failed to new validator: %v", err)
		return
	}
	if err := v.validateAndReport(); err != nil {
		log.Printf("Failed to validateAndReport: %v", err)
		return
	}
	return
}

func (v *validator) validateAndReport() error {
	if !v.isTitleValid() {
		if err := v.postGitHubPRCheckingStatus(ghStatusFailure, "Test failed(title)"); err != nil {
			return err
		}
		return nil
	}
	if !v.isBodyValid() {
		if err := v.postGitHubPRCheckingStatus(ghStatusFailure, "Test failed(body)"); err != nil {
			return err
		}
		return nil
	}
	return v.postGitHubPRCheckingStatus(ghStatusSuccess, "Test passed")
}

var scopeRe = regexp.MustCompile(`^[\/\w]+:\s`)     // scope 格式
var formatRe = regexp.MustCompile(`：|\s{2}|[^\w]$`) // 中文冒号；连续空格；非法末尾

func (v *validator) isTitleValid() bool {
	for _, r := range v.PullRequest.Title {
		if unicode.In(r, unicode.Han, unicode.Latin) || unicode.IsPunct(r) || r == ' ' {
			continue
		} else {
			return false
		}
	}
	if formatRe.Match([]byte(v.PullRequest.Title)) {
		return false
	}
	if !scopeRe.Match([]byte(v.PullRequest.Title)) {
		return false
	}
	return true
}

func (v *validator) isBodyValid() bool {
	for _, r := range v.PullRequest.Body {
		if unicode.In(r, unicode.Han, unicode.Latin) || unicode.IsPunct(r) || unicode.IsSpace(r) {
			continue
		} else {
			return false
		}
	}
	return true
}

func (v *validator) postGitHubPRCheckingStatus(status, description string) error {
	URL := fmt.Sprintf("https://api.github.com/repos/moruowait/bazeldemo/statuses/%s", v.PullRequest.Head.Sha)
	data := map[string]string{
		"state":       status,
		"target_url":  "https://github.com/xreception/depot/wiki/Pull-Request-Title-and-Description",
		"description": description,
		"context":     "Google Cloud Function PR check",
	}
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	client := &http.Client{}
	req, err := http.NewRequest("POST", URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", v.Token))
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("Failed to post GitHub status with response: %v", string(body))
	}
	return nil
}

func getGitHubToken() (string, error) {
	ctx := context.Background()
	cli, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return "", err
	}
	svr, err := cloudkms.New(cli)
	if err != nil {
		return "", err
	}
	return decrypt(svr, encryptedToken)
}

func decrypt(svr *cloudkms.Service, ciphertext string) (string, error) {
	req := &cloudkms.DecryptRequest{
		Ciphertext: ciphertext,
	}
	resp, err := svr.Projects.Locations.KeyRings.CryptoKeys.Decrypt(kmsKey, req).Do()
	if err != nil {
		return "", err
	}
	b, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
