// Package p contains an HTTP Cloud Function.
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

type webhook struct {
	Body        string
	Head        head
	PullRequest pullRequest
}

type pullRequest struct {
	Title string
}

type head struct {
	Sha string
}

var encryptedAK = "CiQA0ev1XO7mUrSoJWceUh6kXkEeExjdebXlIQ9maVLlD6BztVISUQB15DKow2f15qU1QLIETYzK9/rftpgFLIwXdpq6R8pW3IrrQr3Tpl4vCr6zRyMRNam6zeWd8QmTpkd2RVf2Brg5qsX+RJymqGJwndTt1quDjw=="
var kmsKey = "projects/gcp-test-195721/locations/global/keyRings/test/cryptoKeys/github_access_test_key"

// ReportPRValidationStatus check whether PR title and description is valid and report status to GitHub.
func ReportPRValidationStatus(w http.ResponseWriter, r *http.Request) {
	var wh webhook
	if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
		log.Printf("Failed to decode requestBody: %v", err)
		return
	}

	ctx := context.Background()
	cli, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		log.Println(err)
		return
	}
	svr, err := cloudkms.New(cli)
	if err != nil {
		log.Println(err)
		return
	}
	token, err := decrypt(svr, encryptedAK)
	if err != nil {
		log.Println(err)
		return
	}

	if !isTitleValid(wh.PullRequest.Title) {
		io.WriteString(w, "OK")
		if err := postGitHubPRCheckingStatus(wh.Head.Sha, ghStatusFailure, "Test failed", token); err != nil {
			log.Println(err)
		}
		return
	}
	if isBodyValid(wh.Body) {
		io.WriteString(w, "OK")
		if err := postGitHubPRCheckingStatus(wh.Head.Sha, ghStatusFailure, "Test failed", token); err != nil {
			log.Println(err)
		}
		return
	}
	log.Printf("receive: %v", &wh)
	if err := postGitHubPRCheckingStatus(wh.Head.Sha, ghStatusSuccess, "Test passed", token); err != nil {
		log.Println(err)
	}
	io.WriteString(w, "OK")
	return
}

var scopeRe = regexp.MustCompile(`^[\/\w]+:\s+`)
var formatRe = regexp.MustCompile(`：|\s{2}|^.*[^\w]$`)

func isTitleValid(s string) bool {
	for _, r := range s {
		if unicode.In(r, unicode.Han, unicode.Latin) || unicode.IsPunct(r) || r == ' ' {
			continue
		} else {
			return false
		}
	}
	if formatRe.Match([]byte(s)) {
		return false
	}
	if !scopeRe.Match([]byte(s)) {
		return false
	}
	return true
}

func isBodyValid(s string) bool {
	for _, r := range s {
		if unicode.In(r, unicode.Han, unicode.Latin) || unicode.IsPunct(r) || unicode.IsSpace(r) {
			continue
		} else {
			return false
		}
	}
	return true
}

func postGitHubPRCheckingStatus(sha, status, description, token string) error {
	// URL := fmt.Sprintf("https://api.github.com/repos/xreception/depot/statuses/%s", sha)
	URL := fmt.Sprintf("https://api.github.com/repos/moruowait/bazeldemo/statuses/%s", sha)
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
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer resp.Body.Close()
	fmt.Println("status:", resp.StatusCode)
	if resp.StatusCode != http.StatusCreated {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("Failed to post GitHub status with response: %v", string(body))
	}
	return nil
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
