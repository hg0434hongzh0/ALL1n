package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTargets(t *testing.T) {
	t.Parallel()
	raw := "http://a.com\nhttps://b.com;http://a.com, 10.0.0.1:8080\t\n"
	targets := parseTargets(raw)
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}
	if targets[0] != "http://a.com" || targets[1] != "https://b.com" || targets[2] != "10.0.0.1:8080" {
		t.Fatalf("unexpected targets: %#v", targets)
	}
}

func TestLoadTargetsFromFile(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(file, []byte("a.com\nb.com\n"), 0o644); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
	targets, err := loadTargetsFromFile(file)
	if err != nil {
		t.Fatalf("loadTargetsFromFile failed: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
}

func TestImportNucleiTemplatesFromDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := `
id: demo
info:
  name: Demo
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`
	bad := `not-yaml`
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(good), 0o644); err != nil {
		t.Fatalf("write good template failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "b.yml"), []byte(good), 0o644); err != nil {
		t.Fatalf("write nested template failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte(bad), 0o644); err != nil {
		t.Fatalf("write bad template failed: %v", err)
	}

	folder, pocs, err := importNucleiTemplatesFromDir(dir)
	if err != nil {
		t.Fatalf("importNucleiTemplatesFromDir failed: %v", err)
	}
	if !strings.Contains(folder, "Nuclei 批量导入") {
		t.Fatalf("unexpected folder: %s", folder)
	}
	if len(pocs) != 2 {
		t.Fatalf("expected 2 imported pocs, got %d", len(pocs))
	}
	if !strings.Contains(pocs[0].Name, "::") {
		t.Fatalf("expected name prefix from path, got %s", pocs[0].Name)
	}
}
