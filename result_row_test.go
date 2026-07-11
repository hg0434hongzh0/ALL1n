package main

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func TestResultPresentation(t *testing.T) {
	t.Parallel()

	text, importance, colorName, _ := resultPresentation("VULN")
	if text != "已验证 · POC 命中" || importance != widget.SuccessImportance || colorName != theme.ColorNameSuccess {
		t.Fatalf("unexpected VULN presentation: %q %v %v", text, importance, colorName)
	}
	text, importance, colorName, _ = resultPresentation("ERR")
	if text != "验证异常 · 执行错误" || importance != widget.DangerImportance || colorName != theme.ColorNameError {
		t.Fatalf("unexpected ERR presentation: %q %v %v", text, importance, colorName)
	}
}

func TestFormatCompactBytes(t *testing.T) {
	t.Parallel()
	if got := formatCompactBytes(1536); got != "1.5 KiB" {
		t.Fatalf("formatCompactBytes = %q", got)
	}
}

func TestVulnerabilityCardUsesFormalEvidenceHeadline(t *testing.T) {
	t.Parallel()

	result := ExploitResult{
		Level:   "VULN",
		Message: "legacy message",
		Evidence: &HTTPExploitEvidence{
			MatchEvidence: "AND 条件成立\n✓ 响应耗时 5.2s ≥ 阈值 5s",
		},
	}
	if got := resultEvidenceHeadline(result); got != "AND 条件成立" {
		t.Fatalf("resultEvidenceHeadline = %q", got)
	}
	if verdict := resultVerdict(result); !strings.Contains(verdict, "规则成立") {
		t.Fatalf("unexpected formal verdict: %q", verdict)
	}
}
