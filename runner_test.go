package main

import (
	"bytes"
	"encoding/json"
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

func TestEvaluateMatchInvalidRegex(t *testing.T) {
	t.Parallel()

	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	if _, _, err := evaluateMatch(resp, "body", "regex:["); err == nil {
		t.Fatal("expected invalid regex to return error")
	}
}

func TestRunnerTreatsExpectedTimeoutAsVulnerabilityEvidence(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		_, _ = w.Write([]byte("late response"))
	}))
	defer server.Close()

	poc := &POC{
		Name:      "time-based SQL injection",
		Method:    http.MethodGet,
		Path:      "/delay",
		MatchRule: "timeout:true && duration:>=30ms",
	}
	result := NewRunner().Run(server.URL, poc, RunSettings{Timeout: 50 * time.Millisecond})
	if result.Level != "VULN" {
		t.Fatalf("expected timeout rule to produce VULN, got %s: %s", result.Level, result.Message)
	}
	if result.Evidence == nil || !strings.Contains(result.Evidence.MatchEvidence, "达到超时阈值") {
		t.Fatalf("expected timeout match evidence, got %#v", result.Evidence)
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

func TestBuildTargetURLRejectsInvalidTargets(t *testing.T) {
	t.Parallel()

	for _, target := range []string{"http://", "file:///tmp/test"} {
		if _, err := buildTargetURL(target, "/", ""); err == nil {
			t.Fatalf("expected invalid target %q to fail", target)
		}
	}
}

func TestSaveDataCanReplaceExistingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "poc_data.json")
	data := defaultAppData()
	if err := saveDataToFile(path, data); err != nil {
		t.Fatalf("first save failed: %v", err)
	}

	data.Counter++
	if err := saveDataToFile(path, data); err != nil {
		t.Fatalf("second save should replace the existing file: %v", err)
	}

	loaded, err := loadDataFromFile(path)
	if err != nil {
		t.Fatalf("load after replacement failed: %v", err)
	}
	if loaded.Counter != data.Counter {
		t.Fatalf("replacement was not persisted: got counter %d, want %d", loaded.Counter, data.Counter)
	}
}

func TestImportRejectsTrailingJSON(t *testing.T) {
	t.Parallel()

	payload := `{"nodes":{},"root_ids":[],"counter":0} {}`
	if _, err := importData(strings.NewReader(payload)); err == nil {
		t.Fatal("expected trailing JSON object to be rejected")
	}
}

func TestLoadDataRecoversBackup(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "poc_data.json")
	backupPath := path + ".bak"
	data := defaultAppData()
	if err := saveDataToFile(backupPath, data); err != nil {
		t.Fatalf("prepare backup failed: %v", err)
	}

	loaded, err := loadDataFromFile(path)
	if err != nil {
		t.Fatalf("backup recovery failed: %v", err)
	}
	if loaded == nil || len(loaded.Nodes) != len(data.Nodes) {
		t.Fatal("backup data was not recovered")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("recovered backup was not restored to the primary path: %v", err)
	}
}

func TestValidatePOCRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	tests := []POC{
		{Name: "method", Method: "TRACE", MatchRule: "ok"},
		{Name: "header", Method: "GET", Headers: "Broken Header", MatchRule: "ok"},
		{Name: "rule", Method: "GET", MatchRule: "regex:["},
		{Name: "empty", Method: "GET", MatchRule: " "},
	}
	for _, poc := range tests {
		poc := poc
		t.Run(poc.Name, func(t *testing.T) {
			t.Parallel()
			if err := validatePOC(&poc); err == nil {
				t.Fatal("expected invalid POC configuration to fail")
			}
		})
	}
}

func TestRunnerCapturesRedactedHTTPEvidence(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "sessionid=response-secret; HttpOnly")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"access_token":"response-secret","result":"evidence-ok"}`)
	}))
	defer server.Close()

	result := NewRunner().Run(server.URL, &POC{
		Name:      "evidence",
		Method:    http.MethodPost,
		Path:      "/verify",
		Params:    "token=query-secret&mode=test",
		BodyType:  "JSON",
		Body:      `{"username":"admin","password":"body-secret"}`,
		Headers:   "Authorization: Bearer header-secret\nCookie: sessionid=request-secret",
		MatchRule: "status:201 && body:evidence-ok",
	}, RunSettings{Timeout: 5 * time.Second})

	if result.Level != "VULN" || result.Evidence == nil {
		t.Fatalf("expected captured VULN evidence, got level=%s evidence=%v message=%s", result.Level, result.Evidence != nil, result.Message)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, secret := range []string{"query-secret", "body-secret", "header-secret", "request-secret", "response-secret"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("captured evidence leaked %q: %s", secret, encoded)
		}
	}
	if !strings.Contains(result.Evidence.RequestLine, "REDACTED") ||
		!strings.Contains(result.Evidence.RequestHeaders, "REDACTED") ||
		!strings.Contains(result.Evidence.RequestBody, "REDACTED") ||
		!strings.Contains(result.Evidence.ResponseHeaders, "REDACTED") ||
		!strings.Contains(result.Evidence.ResponseBody, "REDACTED") ||
		!strings.Contains(result.Evidence.MatchEvidence, "status 等于 201") {
		t.Fatalf("incomplete evidence: %+v", result.Evidence)
	}
}
