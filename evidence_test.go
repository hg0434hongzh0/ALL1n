package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEvidenceRedactsSensitiveHeadersAndQuery(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com/api?token=secret&id=1", strings.NewReader(`{"password":"demo","name":"alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	evidence := captureRequestEvidence(req, `{"password":"demo","name":"alice"}`)
	combined := evidence.RequestLine + evidence.RequestHeaders + evidence.RequestBody
	for _, secret := range []string{"Bearer secret", `"password":"demo"`, "token=secret"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("evidence leaked %q: %s", secret, combined)
		}
	}
	if !strings.Contains(combined, "[REDACTED]") {
		t.Fatalf("evidence missing redaction marker: %s", combined)
	}
	if !strings.Contains(evidence.RequestBody, `"name": "alice"`) {
		t.Fatalf("non-sensitive JSON field was lost: %s", evidence.RequestBody)
	}
}

func TestEvidenceBodyPreviewTruncates(t *testing.T) {
	body := []byte(strings.Repeat("a", maxEvidenceBodyBytes+32))
	preview, truncated := evidenceBodyPreview(body, "text/plain")
	if !truncated {
		t.Fatal("expected truncated evidence")
	}
	if len(preview) != maxEvidenceBodyBytes {
		t.Fatalf("preview length = %d", len(preview))
	}
}

func TestFormatEvidenceHeadersRedactsCookies(t *testing.T) {
	headers := http.Header{
		"Set-Cookie":   []string{"session=secret"},
		"Content-Type": []string{"text/plain"},
	}
	got := formatEvidenceHeaders(headers, "example.com")
	if strings.Contains(got, "session=secret") {
		t.Fatalf("cookie leaked: %s", got)
	}
	if !strings.Contains(got, "Host: example.com") || !strings.Contains(got, "Content-Type: text/plain") {
		t.Fatalf("expected headers missing: %s", got)
	}
}

func TestFormatProofSummaryContainsScreenshotFields(t *testing.T) {
	t.Parallel()

	result := ExploitResult{
		Target:       "https://example.com",
		POCName:      "time SQLi",
		Method:       "GET",
		URL:          "https://example.com/test",
		Level:        "VULN",
		Duration:     5 * time.Second,
		ResponseSize: 128,
	}
	summary := formatProofSummary(result, "200", "2026-07-11 12:00:00", "✓ 响应耗时 5s ≥ 阈值 5s")
	for _, expected := range []string{"By 基调听云-hongzh0", "time SQLi", "https://example.com", "规则成立", "响应耗时"} {
		if !strings.Contains(summary, expected) {
			t.Fatalf("proof summary missing %q: %s", expected, summary)
		}
	}
}
