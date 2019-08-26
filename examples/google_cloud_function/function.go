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

	encryptedGitHubToken = "CiQA0ev1XJIfg6wmsY7Ln3bbmVqIZVRN0hdsn/L5HXRfb7wTAboSUQB15DKoxvXMvb9vrqco3JVZ46Mw7fBbSBAMCwKD6R33kd0MKQ1QYBsYSeGezwIlk83SwXbqhWZYBLEHgsIJ6mdPFrx76NVf+6x5l5hdxhhlhw=="
	kmsKey               = "projects/gcp-test-195721/locations/global/keyRings/test/cryptoKeys/github_access_test_key"
)

type webhookRequest struct {
	PullRequest struct {
		Body string `json:"body"`
		Head struct {
			Sha string `json:"sha"`
		} `json:"head"`
		StatusesURL string `json:"statuses_url"`
		Title       string `json:"title"`
	} `json:"pull_request"`
}

type validator struct {
	Token string
}

func newValidator(token string) *validator {
	return &validator{
		Token: token,
	}
}

var v *validator

func init() {
	token, err := decryptGitHubToken(context.Background(), encryptedGitHubToken)
	if err != nil {
		log.Printf("Failed to decrypt GitHub Token: %v", err)
		os.Exit(1)
	}
	v = newValidator(token)
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
	if err := v.validateAndReport(&whr); err != nil {
		log.Printf("Failed to validateAndReport: %v", err)
		return
	}
	return
}

func (v *validator) validateAndReport(whr *webhookRequest) error {
	state, msg := v.validate(whr)
	return v.postGitHubPRCheckStatus(whr, state, msg)
}

func (v *validator) validate(whr *webhookRequest) (state string, message string) {
	if err := v.checkTitle(whr); err != nil {
		return ghStatusFailure, err.Error()
	}
	if err := v.checkBody(whr); err != nil {
		return ghStatusFailure, err.Error()
	}
	return ghStatusSuccess, "Test passed"
}

var titleRules = []struct {
	re      *regexp.Regexp
	message string
	want    bool
}{
	{
		re:      regexp.MustCompile(`[\p{Han}\p{Latin}[:punct:]\s]+`),
		message: "should not include invalid characters",
		want:    true,
	},
	{
		re:      regexp.MustCompile(`：`),
		message: "should not include Chinese colon",
		want:    false,
	},
	{
		re:      regexp.MustCompile(`\W$`),
		message: "should not end with non-word-characters",
		want:    false,
	},
	{
		re:      regexp.MustCompile(`\s{2}`),
		message: "should not include continues spaces",
		want:    false,
	},
	{
		re:      regexp.MustCompile(`[\/\w]+:\s`),
		message: "should not include invalid scope",
		want:    true,
	},
}

func (v *validator) checkTitle(whr *webhookRequest) error {
	for _, r := range titleRules {
		if got := r.re.Match([]byte(whr.PullRequest.Title)); got != r.want {
			return fmt.Errorf("Test failed (title: %v)", r.message)
		}
	}
	return nil
}

var bodyRules = []struct {
	re      *regexp.Regexp
	message string
	want    bool
}{
	{
		re:      regexp.MustCompile(`[\p{Han}\p{Latin}[:punct:]\s]+`),
		message: "should not include invalid characters",
		want:    true,
	},
}

func (v *validator) checkBody(whr *webhookRequest) error {
	for _, r := range bodyRules {
		if got := r.re.Match([]byte(whr.PullRequest.Body)); got != r.want {
			return fmt.Errorf("Test failed (body: %v)", r.message)
		}
	}
	return nil
}

func (v *validator) postGitHubPRCheckStatus(whr *webhookRequest, state, description string) error {
	b, err := json.Marshal(struct {
		Context     string `json:"context"`
		Description string `json:"description"`
		State       string `json:"state"`
		TargetURL   string `json:"target_url"`
	}{
		Context:     "Title and description",
		Description: description,
		State:       state,
		TargetURL:   "https://github.com/xreception/depot/wiki/Pull-Request-Title-and-Description",
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, whr.PullRequest.StatusesURL, bytes.NewReader(b))
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
