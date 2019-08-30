// Package prlice 提供了一个 HTTP 方法来验证 pullrequest 的标题及内容是否符合标准格式，并为 pullrequest 创建相应的 status。
package prlice

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"time"

	"cloud.google.com/go/kms/apiv1"
	"github.com/dgrijalva/jwt-go"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type statusState string

const (
	failure statusState = "failure"
	success statusState = "success"

	statusContext   = "Title and description"
	statusTargetURL = "https://github.com/xreception/depot/wiki/Pull-Request-Title-and-Description"

	// encryptedGitHubToken = "CiQA0ev1XJIfg6wmsY7Ln3bbmVqIZVRN0hdsn/L5HXRfb7wTAboSUQB15DKoxvXMvb9vrqco3JVZ46Mw7fBbSBAMCwKD6R33kd0MKQ1QYBsYSeGezwIlk83SwXbqhWZYBLEHgsIJ6mdPFrx76NVf+6x5l5hdxhhlhw=="
	encryptedPEM = "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"
	kmsKey       = "projects/gcp-test-195721/locations/global/keyRings/test/cryptoKeys/github_access_test_key"

	installationAccessTokenEndpoint = "https://api.github.com/app/installations/1705204/access_tokens"
	appID                           = 39801
	expireTime                      = 10 * 60
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
	auth       *authenticate
	titleRules []rule
	bodyRules  []rule
}

type authenticate struct {
	endpoint string
	jwtToken *jwt.Token
	pk       *rsa.PrivateKey
	token    *installationAccessToken
}

func (a *authenticate) getToken() (string, error) {
	if a.token == nil || time.Now().After(a.token.ExpiresAt) {
		t, err := a.genInstallationAccessToken()
		if err != nil {
			return "", err
		}
		a.token = t
	}
	return a.token.Token, nil
}

func (a *authenticate) genInstallationAccessToken() (*installationAccessToken, error) {
	st, err := a.jwtToken.SignedString(a.pk)
	if err != nil {
		return nil, err
	}
	return a.newInstallationAccessToken(st)
}

func (a *authenticate) newInstallationAccessToken(signedToken string) (*installationAccessToken, error) {
	req, err := http.NewRequest(http.MethodPost, a.endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.machine-man-preview+json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", signedToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to create installation access_token with response: %q", body)
	}
	var t installationAccessToken
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, err
	}
	log.Println(t)
	return &t, nil
}

type installationAccessToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

var v = pullRequestMessageValidator{
	auth: &authenticate{
		endpoint: installationAccessTokenEndpoint,
		jwtToken: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iat": time.Now().Unix(),
			"exp": time.Now().Unix() + expireTime,
			"iss": appID,
		}),
		pk: mustGeneratePrivateKey(context.Background(), encryptedPEM),
	},
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

func mustGeneratePrivateKey(ctx context.Context, ciphertext string) *rsa.PrivateKey {
	b, err := decrypt(ctx, ciphertext)
	if err != nil {
		panic(err)
	}
	pk, err := jwt.ParseRSAPrivateKeyFromPEM(b)
	if err != nil {
		panic(err)
	}
	return pk
}

func decrypt(ctx context.Context, ciphertext string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	cli, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := cli.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       kmsKey,
		Ciphertext: b,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
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
	token, err := v.auth.getToken()
	if err != nil {
		return err
	}
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
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
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
