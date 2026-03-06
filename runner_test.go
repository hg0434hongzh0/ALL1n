package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
