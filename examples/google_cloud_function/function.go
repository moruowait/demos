// Package p contains an HTTP Cloud Function.
package p

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"unicode"
)

// HelloWorld prints the JSON encoded "message" field in the body
// of the request or "Hello, World!" if there isn't one.
func HelloWorld(w http.ResponseWriter, r *http.Request) {
	var d struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		fmt.Fprint(w, "Hello World!")
		return
	}
	if d.Message == "" {
		fmt.Fprint(w, "Hello World!")
		return
	}
	fmt.Fprint(w, html.EscapeString(d.Message))
}

var scopeRe = regexp.MustCompile(`^[\/\w]+:\s+`)
var formatRe = regexp.MustCompile(`：|\s{2}|^.*[^\w]$`)

func isValid(s string) bool {
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
