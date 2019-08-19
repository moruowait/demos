// Package p contains an HTTP Cloud Function.
package p

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"regexp"
	"unicode"
)

type webhook struct {
	PullRequest pullRequest
	Body        string
}

type pullRequest struct {
	Title string
}

// ReportPRValidationStatus check whether PR title and description is valid and report status to GitHub.
func ReportPRValidationStatus(w http.ResponseWriter, r *http.Request) {

	var wh webhook
	if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
		log.Printf("Failed to decode requestBody: %v", err)
		return
	}
	if !isTitleValid(wh.PullRequest.Title) {
		io.WriteString(w, "OK")
		// report status
		return
	}
	if isBodyValid(wh.Body) {
		io.WriteString(w, "OK")
		// report status
		return
	}
	log.Printf("receive: %v", &wh)
	// report status
	io.WriteString(w, "OK")
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
