package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestExportResultsHTMLEscapesAndRedactsEvidence(t *testing.T) {
	results := []ExploitResult{{
		Target: "https://example.com", POCName: `<script>alert(1)</script>`, Level: "VULN",
		URL: "https://example.com/?token=secret", TestedAt: time.Now(),
		Evidence: &HTTPExploitEvidence{
			RequestLine:    "GET /?token=secret HTTP/1.1",
			RequestHeaders: "Authorization: Bearer secret\nAccept: */*",
			ResponseBody:   `{"access_token":"secret","ok":true}`,
		},
	}}
	var output bytes.Buffer
	if err := exportResultsHTML(&output, results); err != nil {
		t.Fatalf("exportResultsHTML() error = %v", err)
	}
	html := output.String()
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Fatal("HTML output did not escape POC name")
	}
	for _, secret := range []string{"Bearer secret", "token=secret", `"access_token":"secret"`} {
		if strings.Contains(html, secret) {
			t.Fatalf("HTML report leaked %q", secret)
		}
	}
	if !strings.Contains(html, "[REDACTED]") || !strings.Contains(html, "ALL1n 验证报告") {
		t.Fatal("HTML report missing expected content")
	}
}
