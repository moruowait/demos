// Package prlice 提供了一个 HTTP 方法来验证 pullrequest 的标题及内容是否符合标准格式，并为 pullrequest 创建相应的 status。
package prlice

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

	"cloud.google.com/go/kms/apiv1"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type statusState string

const (
	failure statusState = "failure"
	success statusState = "success"

	statusContext   = "Title and description"
	statusTargetURL = "https://github.com/xreception/depot/wiki/Pull-Request-Title-and-Description"

	// encryptedGitHubToken = "CiQA0ev1XJIfg6wmsY7Ln3bbmVqIZVRN0hdsn/L5HXRfb7wTAboSUQB15DKoxvXMvb9vrqco3JVZ46Mw7fBbSBAMCwKD6R33kd0MKQ1QYBsYSeGezwIlk83SwXbqhWZYBLEHgsIJ6mdPFrx76NVf+6x5l5hdxhhlhw=="
	encryptedGitHubToken = "CiQA0ev1XCpcV5cYqbG3UOey7jsRpN9HfEwozf+Kyeqcjl5p/N8SVAB15DKorR3S2WMHIeLurF0XuVenhOPiOQagYKyvysOxOZPVJar/HIEQS/ZLmdQigZMQnuHHzdyXPSSKk2MMBiV3C6koP1FOKwDPBTyymgbKZIeaHw=="
	kmsKey               = "projects/gcp-test-195721/locations/global/keyRings/test/cryptoKeys/github_access_test_key"
)

type webhookRequest struct {
	PullRequest *pullRequest `json:"pull_request"`
}

type pullRequest struct {
	Body        string `json:"body"`
	StatusesURL string `json:"statuses_url"`
	Title       string `json:"title"`
}

type rule struct {
	re          *regexp.Regexp
	name        string
	shouldMatch bool
}

type pullRequestMessageValidator struct {
	token      string
	titleRules []rule
	bodyRules  []rule
}

var v = pullRequestMessageValidator{
	token: mustDecrypt(context.Background(), encryptedGitHubToken),
	titleRules: []rule{
		{
			re:          regexp.MustCompile(`[^\p{Han}\p{Latin}[:punct:]\d\s，、￥]+`),
			name:        "should not include invalid characters",
			shouldMatch: false,
		},
		{
			re:          regexp.MustCompile(`：`),
			name:        "should not include Chinese colon",
			shouldMatch: false,
		},
		{
			re:          regexp.MustCompile(`(?:\(#\d+\)|[\p{Han}\w]+)$`),
			name:        "should end with '(#xxx)' or words",
			shouldMatch: true,
		},
		{
			re:          regexp.MustCompile(`\s{2}`),
			name:        "should not include continuous whitespaces",
			shouldMatch: false,
		},
		{
			re:          regexp.MustCompile(`^(revert: )?[\/\w{},]+: `),
			name:        "should have a valid scope",
			shouldMatch: true,
		},
	},
	bodyRules: []rule{
		{
			re:          regexp.MustCompile(`[^\p{Han}\p{Latin}[:punct:]\d\s，、￥]+`),
			name:        "should not include invalid characters",
			shouldMatch: false,
		},
	},
}

func mustDecrypt(ctx context.Context, ciphertext string) string {
	b, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		panic(err)
	}
	cli, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		panic(err)
	}
	resp, err := cli.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       kmsKey,
		Ciphertext: b,
	})
	if err != nil {
		panic(err)
	}
	return string(resp.Plaintext)
}

// HandleWebhook handles a github webhook request.
func HandleWebhook(w http.ResponseWriter, r *http.Request) {
	var whr webhookRequest
	if err := json.NewDecoder(r.Body).Decode(&whr); err != nil {
		log.Printf("Failed to decode requestBody: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, fmt.Sprintf("Failed to decode requestBody: %v", err))
		return
	}
	if err := v.report(whr.PullRequest, v.validate(whr.PullRequest)); err != nil {
		log.Printf("Failed to report: %v", err)
		return
	}
	return
}

func (v *pullRequestMessageValidator) validate(pr *pullRequest) error {
	if err := v.validateTitle(pr); err != nil {
		return err
	}
	if err := v.validateBody(pr); err != nil {
		return err
	}
	return nil
}

func (v *pullRequestMessageValidator) report(pr *pullRequest, err error) error {
	if err != nil {
		return v.postStatus(pr, failure, err.Error())
	}
	return v.postStatus(pr, success, "Test passed")
}

func (v *pullRequestMessageValidator) validateTitle(pr *pullRequest) error {
	for _, r := range v.titleRules {
		if got, want := r.re.MatchString(pr.Title), r.shouldMatch; got != want {
			return fmt.Errorf("title: %v", r.name)
		}
	}
	return nil
}

func (v *pullRequestMessageValidator) validateBody(pr *pullRequest) error {
	for _, r := range v.bodyRules {
		if got, want := r.re.MatchString(pr.Body), r.shouldMatch; got != want {
			return fmt.Errorf("body: %v", r.name)
		}
	}
	return nil
}

func (v *pullRequestMessageValidator) postStatus(pr *pullRequest, state statusState, description string) error {
	b, err := json.Marshal(struct {
		Context     string      `json:"context"`
		Description string      `json:"description"`
		State       statusState `json:"state"`
		TargetURL   string      `json:"target_url"`
	}{
		Context:     statusContext,
		Description: description,
		State:       state,
		TargetURL:   statusTargetURL,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, pr.StatusesURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", v.token))
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
