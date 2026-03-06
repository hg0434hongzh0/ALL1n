package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildTargetURL(t *testing.T) {
	t.Parallel()

	fullURL, err := buildTargetURL("example.com:8080/base", "api/login", "id=1&debug=true")
	if err != nil {
		t.Fatalf("buildTargetURL returned error: %v", err)
	}

	if !strings.HasPrefix(fullURL, "http://example.com:8080/base/api/login?") {
		t.Fatalf("unexpected URL prefix: %s", fullURL)
	}
	if !strings.Contains(fullURL, "id=1") || !strings.Contains(fullURL, "debug=true") {
		t.Fatalf("unexpected query string: %s", fullURL)
	}
}

func TestBuildTargetURLWithAbsolutePath(t *testing.T) {
	t.Parallel()

	fullURL, err := buildTargetURL("http://example.com", "https://demo.local/path", "id=1")
	if err != nil {
		t.Fatalf("buildTargetURL returned error: %v", err)
	}
	if fullURL != "https://demo.local/path?id=1" {
		t.Fatalf("unexpected absolute URL: %s", fullURL)
	}
}

func TestEvaluateMatch(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Server": []string{"nginx/1.24"},
		},
	}

	matched, reason, err := evaluateMatch(resp, "Welcome Admin", "status:2xx && header:Server=nginx && body:Welcome")
	if err != nil {
		t.Fatalf("evaluateMatch returned error: %v", err)
	}
	if !matched {
		t.Fatalf("expected match, got false with reason: %s", reason)
	}
}

func TestEvaluateMatchWithOrAndNegation(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		StatusCode: 302,
		Header: http.Header{
			"Location": []string{"/admin"},
		},
	}

	matched, reason, err := evaluateMatch(resp, "redirecting", "status:200 || (status:302 && !body:forbidden)")
	if err != nil {
		t.Fatalf("evaluateMatch returned error: %v", err)
	}
	if !matched {
		t.Fatalf("expected match, got false with reason: %s", reason)
	}
}

func TestEvaluateMatchInvalidRegex(t *testing.T) {
	t.Parallel()

	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	if _, _, err := evaluateMatch(resp, "body", "regex:["); err == nil {
		t.Fatal("expected invalid regex to return error")
	}
}

func TestDefaultDataRoundTrip(t *testing.T) {
	t.Parallel()

	data := defaultAppData()
	if err := data.validate(); err != nil {
		t.Fatalf("default data should be valid: %v", err)
	}

	if got := len(data.collectPOCs(data.RootIDs[0])); got != 2 {
		t.Fatalf("expected 2 POCs in default data, got %d", got)
	}

	tempFile := filepath.Join(t.TempDir(), "poc_data.json")
	if err := saveDataToFile(tempFile, data); err != nil {
		t.Fatalf("saveDataToFile returned error: %v", err)
	}

	if _, err := os.Stat(tempFile); err != nil {
		t.Fatalf("expected saved data file to exist: %v", err)
	}

	loaded, err := loadDataFromFile(tempFile)
	if err != nil {
		t.Fatalf("loadDataFromFile returned error: %v", err)
	}

	if len(loaded.RootIDs) != len(data.RootIDs) || len(loaded.Nodes) != len(data.Nodes) {
		t.Fatalf("loaded data shape mismatch: roots=%d/%d nodes=%d/%d", len(loaded.RootIDs), len(data.RootIDs), len(loaded.Nodes), len(data.Nodes))
	}
}

func TestRunnerRunChainedPOC(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.Header().Set("Set-Cookie", "sid=abc123; Path=/")
			_, _ = io.WriteString(w, "token=pass123")
		case "/check":
			if r.URL.Query().Get("token") != "pass123" {
				http.Error(w, "missing token", http.StatusBadRequest)
				return
			}
			cookie, err := r.Cookie("sid")
			if err != nil || cookie.Value != "abc123" {
				http.Error(w, "missing cookie", http.StatusForbidden)
				return
			}
			_, _ = io.WriteString(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	runner := NewRunner()
	poc := &POC{
		Name: "chain",
		Steps: []RequestStep{
			{
				Name:         "login",
				Method:       "GET",
				Path:         "/login",
				ExtractRules: "token=body_regex:token=([a-z0-9]+)",
			},
			{
				Name:      "check",
				Method:    "GET",
				Path:      "/check",
				Params:    "token={{token}}",
				MatchRule: "status:200 && body:ok",
			},
		},
	}

	result := runner.Run(server.URL, poc, RunSettings{Timeout: 3 * time.Second})
	if result.Level != "VULN" {
		t.Fatalf("expected VULN, got %s: %s", result.Level, result.Message)
	}
	if len(result.StepResults) != 2 {
		t.Fatalf("expected 2 step results, got %d", len(result.StepResults))
	}
}

func TestImportNucleiTemplate(t *testing.T) {
	t.Parallel()

	template := `
id: chain-test
info:
  name: Demo Nuclei Chain
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/login"
    extractors:
      - type: regex
        name: token
        part: body
        regex:
          - "token=([a-z0-9]+)"
  - raw:
      - |
        GET /check?token={{token}} HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - ok
`

	folderName, pocs, err := importNucleiTemplate(strings.NewReader(template))
	if err != nil {
		t.Fatalf("importNucleiTemplate returned error: %v", err)
	}
	if !strings.Contains(folderName, "Demo Nuclei Chain") {
		t.Fatalf("unexpected folder name: %s", folderName)
	}
	if len(pocs) != 1 {
		t.Fatalf("expected 1 POC, got %d", len(pocs))
	}
	if len(pocs[0].Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(pocs[0].Steps))
	}
	if !strings.Contains(pocs[0].Steps[1].MatchRule, "status:200") {
		t.Fatalf("expected status rule to be imported, got %q", pocs[0].Steps[1].MatchRule)
	}
}
