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

	"cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

const (
	ghStatusFailure = "failure"
	ghStatusSuccess = "success"

	ghContext   = "Title and description"
	ghTargetURL = "https://github.com/xreception/depot/wiki/Pull-Request-Title-and-Description"

	encryptedGitHubToken = "CiQA0ev1XJIfg6wmsY7Ln3bbmVqIZVRN0hdsn/L5HXRfb7wTAboSUQB15DKoxvXMvb9vrqco3JVZ46Mw7fBbSBAMCwKD6R33kd0MKQ1QYBsYSeGezwIlk83SwXbqhWZYBLEHgsIJ6mdPFrx76NVf+6x5l5hdxhhlhw=="
	kmsKey               = "projects/gcp-test-195721/locations/global/keyRings/test/cryptoKeys/github_access_test_key"
)

type webhookRequest struct {
	PullRequest pullRequest `json:"pull_request"`
}

type pullRequest struct {
	Body        string `json:"body"`
	StatusesURL string `json:"statuses_url"`
	Title       string `json:"title"`
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
	cli, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return "", err
	}
	resp, err := cli.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       kmsKey,
		Ciphertext: b,
	})
	if err != nil {
		return "", err
	}
	return string(resp.Plaintext), nil
}

// HandleWebhook handles a github webhook request.
func HandleWebhook(w http.ResponseWriter, r *http.Request) {
	var whr webhookRequest
	if err := json.NewDecoder(r.Body).Decode(&whr); err != nil {
		log.Printf("Failed to decode requestBody: %v", err)
		return
	}
	if err := v.validatePullRequestMessageAndReport(&whr); err != nil {
		log.Printf("Failed to validatePullRequestMessageAndReport: %v", err)
		return
	}
	return
}

func (v *validator) validatePullRequestMessageAndReport(whr *webhookRequest) error {
	if err := v.validate(whr); err != nil {
		return v.postGitHubPRCheckStatus(whr, ghStatusFailure, err.Error())
	}
	return v.postGitHubPRCheckStatus(whr, ghStatusSuccess, "Test passed")
}

func (v *validator) validate(whr *webhookRequest) error {
	if err := v.checkTitle(whr); err != nil {
		return err
	}
	if err := v.checkBody(whr); err != nil {
		return err
	}
	return nil
}

var titleRules = []struct {
	re          *regexp.Regexp
	name        string
	shouldMatch bool
}{
	{
		re:          regexp.MustCompile(`[^\p{Han}\p{Latin}[:punct:][:digit:]\s]+`),
		name:        "should not include invalid characters",
		shouldMatch: false,
	},
	{
		re:          regexp.MustCompile(`：`),
		name:        "should not include Chinese colon",
		shouldMatch: false,
	},
	{
		re:          regexp.MustCompile(`[^\p{Han}\p{Latin}[:digit:])]$`),
		name:        "should not end with non-word-characters",
		shouldMatch: false,
	},
	{
		re:          regexp.MustCompile(`\s{2}`),
		name:        "should not include continuous whitespaces",
		shouldMatch: false,
	},
	{
		re:          regexp.MustCompile(`^(revert: )?[\/\w]+: `),
		name:        "should have a scope",
		shouldMatch: true,
	},
}

func (v *validator) checkTitle(whr *webhookRequest) error {
	for _, r := range titleRules {
		if got, want := r.re.MatchString(whr.PullRequest.Title), r.shouldMatch; got != want {
			return fmt.Errorf("Test failed (title: %v)", r.name)
		}
	}
	return nil
}

var bodyRules = []struct {
	re          *regexp.Regexp
	name        string
	shouldMatch bool
}{
	{
		re:          regexp.MustCompile(`[^\p{Han}\p{Latin}[:punct:][:digit:]\s]+`),
		name:        "should not include invalid characters",
		shouldMatch: false,
	},
}

func (v *validator) checkBody(whr *webhookRequest) error {
	for _, r := range bodyRules {
		if got, want := r.re.MatchString(whr.PullRequest.Body), r.shouldMatch; got != want {
			return fmt.Errorf("Test failed (body: %v)", r.name)
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
		Context:     ghContext,
		Description: description,
		State:       state,
		TargetURL:   ghTargetURL,
	})
	if err != nil {
		return err
	}
	log.Printf("whr.PullRequest.StatusesURL:", whr.PullRequest.StatusesURL)
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
		return fmt.Errorf("failed to post GitHub status with response: %q", body)
	}
	return nil
}
