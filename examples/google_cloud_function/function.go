package pullrequest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

const (
	ghStatusFailure = "failure"
	ghStatusSuccess = "success"

	encryptedGitHubToken = "CiQA0ev1XHH7SG+rHF4wWeA4c2Qi/SlPU9AqIiqh+CgK93arH+cSUgB15DKociD2RU3w8gYwsTOl3/X7WDLJxYmuA8Y2XRkuXalB3wqdg5gShXba3BjUy7Pzhl2Ee/iuX8PCFOiMLIsdQoFBKtknwzrcr2cANnLYpyc="
	kmsKey               = "projects/gcp-test-195721/locations/global/keyRings/test/cryptoKeys/github_access_test_key"
)

type pullRequest struct {
	Head  head
	Title string
	Body  string
}

type head struct {
	Sha string
}

type webhookRequest struct {
	PullRequest pullRequest `json:"pull_request"`
}

type validator struct {
	Token string
}

var v validator

func init() {
	token, err := decryptGitHubToken(context.Background(), encryptedGitHubToken)
	if err != nil {
		log.Printf("Failed to decrypt GitHub Token: %v", err)
		os.Exit(1)
	}
	v.Token = token
}

func decryptGitHubToken(ctx context.Context, ciphertext string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	cli, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return "", err
	}
	req := &kmspb.DecryptRequest{
		Name:       kmsKey,
		Ciphertext: b,
	}

	resp, err := cli.Decrypt(ctx, req)
	if err != nil {
		return "", err
	}
	return string(resp.Plaintext), nil
}

// ValidatePullRequest check whether PR title and description is valid and report status to GitHub.
func ValidatePullRequest(w http.ResponseWriter, r *http.Request) {
	var whr webhookRequest
	if err := json.NewDecoder(r.Body).Decode(&whr); err != nil {
		log.Printf("failed to decode requestBody: %v", err)
		return
	}
	if err := v.validateAndReport(whr); err != nil {
		log.Printf("Failed to validateAndReport: %v", err)
		return
	}
	return
}

func (v *validator) validateAndReport(whr webhookRequest) error {
	requestURL := fmt.Sprintf("https://api.github.com/repos/moruowait/bazeldemo/statuses/%s", whr.PullRequest.Head.Sha)
	if reason, valid := v.checkTitle(whr); !valid {
		if err := v.postGitHubPRCheckStatus(requestURL, ghStatusFailure, fmt.Sprintf("Test failed (title: %v)", reason)); err != nil {
			return err
		}
		return nil
	}
	if reason, valid := v.checkBody(whr); !valid {
		if err := v.postGitHubPRCheckStatus(requestURL, ghStatusFailure, fmt.Sprintf("Test failed (body: %v)", reason)); err != nil {
			return err
		}
		return nil
	}
	return v.postGitHubPRCheckStatus(requestURL, ghStatusSuccess, "Test passed")
}

var titleRules = []struct {
	re      *regexp.Regexp
	message string
	match   bool
}{
	{
		re:      regexp.MustCompile(`[\p{Han}\p{Latin}[:punct:]\s]+`),
		message: "should not include invalid characters",
		match:   true,
	},
	{
		re:      regexp.MustCompile(`：`),
		message: "should not include Chinese colon",
		match:   true,
	},
	{
		re:      regexp.MustCompile(`\W$`),
		message: "should not end with non-word-characters",
		match:   true,
	},
	{
		re:      regexp.MustCompile(`\s{2}`),
		message: "should not include continues spaces",
		match:   true,
	},
	{
		re:      regexp.MustCompile(`[\/\w]+:\s`),
		message: "should not include invalid scope",
		match:   false,
	},
}

func (v *validator) checkTitle(whr webhookRequest) (reason string, valid bool) {
	for _, r := range titleRules {
		if r.match == r.re.Match([]byte(whr.PullRequest.Title)) {
			return r.message, false
		}
	}
	return "", true
}

var bodyRules = []struct {
	re      *regexp.Regexp
	message string
	match   bool
}{
	{
		re:      regexp.MustCompile(`[\p{Han}\p{Latin}[:punct:]\s]+`),
		message: "should not include invalid characters",
		match:   true,
	},
}

func (v *validator) checkBody(whr webhookRequest) (reason string, valid bool) {
	for _, r := range bodyRules {
		if r.match == r.re.Match([]byte(whr.PullRequest.Body)) {
			return r.message, false
		}
	}
	return "", true
}

type gitHubStatus struct {
	Context     string `json:"context"`
	Description string `json:"description"`
	State       string `json:"state"`
	TargetURL   string `json:"target_url"`
}

func (v *validator) postGitHubPRCheckStatus(requestURL, state, description string) error {
	b, err := json.Marshal(gitHubStatus{
		Context:     "Title and description",
		TargetURL:   "https://github.com/xreception/depot/wiki/Pull-Request-Title-and-Description",
		State:       state,
		Description: description,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", v.Token))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("failed to post GitHub status with response: %v", string(body))
	}
	return nil
}
