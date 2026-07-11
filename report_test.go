package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunnerCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(2 * time.Second):
			_, _ = io.WriteString(w, "late")
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := NewRunner().RunContext(ctx, server.URL, &POC{Name: "cancel", Method: "GET", MatchRule: "late"}, RunSettings{Timeout: 5 * time.Second})
	if result.Level != "CANCEL" {
		t.Fatalf("expected CANCEL, got %s: %s", result.Level, result.Message)
	}
}

func TestRunnerTruncatesLargeResponses(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("A", int(maxResponseBodyBytes)+128))
	}))
	defer server.Close()

	result := NewRunner().Run(server.URL, &POC{Name: "large", Method: "GET", MatchRule: "body:AAA"}, RunSettings{Timeout: 5 * time.Second})
	if result.Level != "VULN" {
		t.Fatalf("expected VULN, got %s: %s", result.Level, result.Message)
	}
	if !result.Truncated || result.ResponseSize != maxResponseBodyBytes {
		t.Fatalf("unexpected truncation metadata: truncated=%v size=%d", result.Truncated, result.ResponseSize)
	}
}

func TestExportResultsJSON(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	results := []ExploitResult{{POCName: "demo", Level: "VULN", TestedAt: time.Now()}}
	if err := exportResultsJSON(&output, results); err != nil {
		t.Fatalf("exportResultsJSON failed: %v", err)
	}

	var report resultReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON report: %v", err)
	}
	if report.Summary.Vulnerable != 1 || len(report.Results) != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestExportResultsCSVPreventsFormulaInjection(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	results := []ExploitResult{{Target: "=target", POCName: "=CMD()", URL: "+http://example", Message: "@payload", Level: "SAFE"}}
	if err := exportResultsCSV(&output, results); err != nil {
		t.Fatalf("exportResultsCSV failed: %v", err)
	}

	reader := csv.NewReader(strings.NewReader(strings.TrimPrefix(output.String(), "\ufeff")))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("invalid CSV report: %v", err)
	}
	if got := records[1][2]; got != "'=target" {
		t.Fatalf("target was not sanitized: %q", got)
	}
	if got := records[1][3]; got != "'=CMD()" {
		t.Fatalf("POC name was not sanitized: %q", got)
	}
	if got := records[1][5]; got != "'+http://example" {
		t.Fatalf("URL was not sanitized: %q", got)
	}
}

func TestExportResultsJSONIncludesRedactedEvidence(t *testing.T) {
	t.Parallel()

	results := []ExploitResult{{
		Target:  "https://example.com/?api_key=target-secret",
		URL:     "https://example.com/check?token=url-secret",
		POCName: "evidence",
		Level:   "VULN",
		Evidence: &HTTPExploitEvidence{
			RequestLine:     "POST /check?token=request-secret HTTP/1.1",
			RequestHeaders:  "Authorization: Bearer header-secret",
			RequestBody:     `{"password":"body-secret"}`,
			ResponseHeaders: "Set-Cookie: sessionid=cookie-secret",
			ResponseBody:    `{"access_token":"response-secret"}`,
		},
	}}
	var output bytes.Buffer
	if err := exportResultsJSON(&output, results); err != nil {
		t.Fatalf("exportResultsJSON failed: %v", err)
	}
	for _, secret := range []string{"target-secret", "url-secret", "request-secret", "header-secret", "body-secret", "cookie-secret", "response-secret"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("JSON report leaked %q: %s", secret, output.String())
		}
	}
	if !strings.Contains(output.String(), `"evidence"`) || !strings.Contains(output.String(), "[REDACTED]") {
		t.Fatal("JSON report did not include redacted evidence")
	}
}
