package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func matchTestResponse(status int, headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: headers}
}

func TestEvaluateMatchORAcrossResponseSources(t *testing.T) {
	t.Parallel()

	resp := matchTestResponse(200, http.Header{"Server": []string{"nginx/1.24"}})
	tests := []struct {
		name string
		rule string
		body string
	}{
		{"status branch", "status:404 || status:200", ""},
		{"header branch", "status:500 OR header:Server=nginx", ""},
		{"body branch", "status:500 或 body:Welcome", "Welcome Admin"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			matched, reason, err := evaluateMatch(resp, tt.body, tt.rule)
			if err != nil {
				t.Fatalf("evaluateMatch returned error: %v", err)
			}
			if !matched {
				t.Fatalf("expected %q to match: %s", tt.rule, reason)
			}
			if !strings.Contains(reason, "OR 条件成立") || !strings.Contains(reason, "✓") || !strings.Contains(reason, "✗") {
				t.Fatalf("expected readable OR evidence, got %q", reason)
			}
		})
	}
}

func TestEvaluateMatchANDHasHigherPrecedenceThanOR(t *testing.T) {
	t.Parallel()

	resp := matchTestResponse(200, nil)
	matched, reason, err := evaluateMatch(resp, "nothing useful", "status:200 || status:404 && body:missing")
	if err != nil {
		t.Fatalf("evaluateMatch returned error: %v", err)
	}
	if !matched {
		t.Fatalf("AND should have higher precedence than OR: %s", reason)
	}
}

func TestEvaluateMatchStatusHeaderBodyAND(t *testing.T) {
	t.Parallel()

	resp := matchTestResponse(204, http.Header{"X-Product": []string{"U8Cloud"}})
	matched, reason, err := evaluateMatch(resp, "operation success", "status:2xx 和 header:X-Product=U8Cloud AND body:success")
	if err != nil {
		t.Fatalf("evaluateMatch returned error: %v", err)
	}
	if !matched {
		t.Fatalf("expected mixed AND aliases to match: %s", reason)
	}
	if !strings.Contains(reason, "AND 条件成立") {
		t.Fatalf("expected readable AND evidence, got %q", reason)
	}
}

func TestLegacyCompactANDRuleStillWorks(t *testing.T) {
	t.Parallel()

	resp := matchTestResponse(200, http.Header{"Server": []string{"nginx"}})
	matched, _, err := evaluateMatch(resp, "Welcome", "status:200&&header:Server=nginx&&body:Welcome")
	if err != nil {
		t.Fatalf("evaluateMatch returned error: %v", err)
	}
	if !matched {
		t.Fatal("legacy compact && rule should still match")
	}
}

func TestCompactORRuleStillWorks(t *testing.T) {
	t.Parallel()

	matched, _, err := evaluateMatch(matchTestResponse(302, nil), "", "status:200||status:302")
	if err != nil {
		t.Fatalf("evaluateMatch returned error: %v", err)
	}
	if !matched {
		t.Fatal("compact || rule should match typed conditions")
	}
}

func TestRegexDoublePipeWithoutOperatorSpacingIsPreserved(t *testing.T) {
	t.Parallel()

	matched, _, err := evaluateMatch(matchTestResponse(200, nil), "foobar", `regex:foo||bar`)
	if err != nil {
		t.Fatalf("regex containing || should remain a single condition: %v", err)
	}
	if !matched {
		t.Fatal("regex containing || should match")
	}
}

func TestValidateMatchRuleRejectsMalformedBooleanExpressions(t *testing.T) {
	t.Parallel()

	for _, rule := range []string{
		"status:200 ||",
		"|| body:ok",
		"status:200 && || body:ok",
		"status:200 AND",
		"或 body:ok",
	} {
		rule := rule
		t.Run(rule, func(t *testing.T) {
			t.Parallel()
			if err := validateMatchRule(rule); err == nil {
				t.Fatalf("expected malformed rule %q to fail validation", rule)
			}
		})
	}
}

func TestEvaluateMatchAllORBranchesFailIncludesEvidence(t *testing.T) {
	t.Parallel()

	matched, reason, err := evaluateMatch(matchTestResponse(404, nil), "denied", "status:200 || body:Welcome")
	if err != nil {
		t.Fatalf("evaluateMatch returned error: %v", err)
	}
	if matched {
		t.Fatal("expected all OR branches to fail")
	}
	if !strings.Contains(reason, "0/2") || strings.Count(reason, "✗") != 2 {
		t.Fatalf("expected evidence from both failed branches, got %q", reason)
	}
}

func TestEvaluateDurationCondition(t *testing.T) {
	t.Parallel()

	resp := matchTestResponse(200, nil)
	matched, reason, err := evaluateMatchContext(resp, "OK", "duration:>=5s && status:200", 5200*time.Millisecond, false)
	if err != nil {
		t.Fatalf("evaluateMatchContext returned error: %v", err)
	}
	if !matched {
		t.Fatalf("expected delayed response to match: %s", reason)
	}
	if !strings.Contains(reason, "响应耗时 5.2s") {
		t.Fatalf("expected duration evidence, got %q", reason)
	}
}

func TestEvaluateDurationAliasesAndComparators(t *testing.T) {
	t.Parallel()

	resp := matchTestResponse(200, nil)
	for _, rule := range []string{"time:>1500ms", "elapsed:<=3s", "duration:2s"} {
		matched, reason, err := evaluateMatchContext(resp, "", rule, 2*time.Second, false)
		if err != nil {
			t.Fatalf("rule %q returned error: %v", rule, err)
		}
		if !matched {
			t.Fatalf("expected rule %q to match: %s", rule, reason)
		}
	}
}

func TestEvaluateExpectedTimeoutCondition(t *testing.T) {
	t.Parallel()

	matched, reason, err := evaluateMatchContext(nil, "", "timeout:true && duration:>=3s", 3*time.Second, true)
	if err != nil {
		t.Fatalf("evaluateMatchContext returned error: %v", err)
	}
	if !matched {
		t.Fatalf("expected timeout condition to match: %s", reason)
	}
	if !strings.Contains(reason, "达到超时阈值") {
		t.Fatalf("expected timeout evidence, got %q", reason)
	}
}

func TestTimeoutCannotSatisfyResponseCondition(t *testing.T) {
	t.Parallel()

	matched, reason, err := evaluateMatchContext(nil, "", "timeout:true && body:Welcome", 5*time.Second, true)
	if err != nil {
		t.Fatalf("evaluateMatchContext returned error: %v", err)
	}
	if matched {
		t.Fatal("timeout without a response must not satisfy a body condition")
	}
	if !strings.Contains(reason, "未获得 HTTP 响应") {
		t.Fatalf("expected missing-response evidence, got %q", reason)
	}
}

func TestValidateDurationAndTimeoutRules(t *testing.T) {
	t.Parallel()

	for _, rule := range []string{"duration:five", "duration:0s", "timeout:maybe", "elapsed:", "time:>=-1s"} {
		if err := validateMatchRule(rule); err == nil {
			t.Fatalf("expected rule %q to fail validation", rule)
		}
	}
}
