package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// matchExpression is an OR-list of AND-groups. AND therefore has higher
// precedence than OR while legacy rules containing only && keep their meaning.
type matchExpression struct {
	groups [][]string
}

type matchToken struct {
	condition string
	operator  string
}

type matchContext struct {
	response *http.Response
	body     string
	duration time.Duration
	timedOut bool
}

func parseMatchExpression(rule string) (matchExpression, error) {
	trimmed := strings.TrimSpace(rule)
	if trimmed == "" {
		return matchExpression{}, fmt.Errorf("匹配规则不能为空")
	}

	tokens, err := tokenizeMatchRule(trimmed)
	if err != nil {
		return matchExpression{}, err
	}
	if len(tokens) == 0 || tokens[0].condition == "" {
		return matchExpression{}, fmt.Errorf("匹配规则缺少条件")
	}

	expression := matchExpression{groups: [][]string{{tokens[0].condition}}}
	for i := 1; i < len(tokens); i++ {
		token := tokens[i]
		if token.condition == "" {
			return matchExpression{}, fmt.Errorf("运算符 %s 后缺少匹配条件", token.operator)
		}
		switch token.operator {
		case "AND":
			last := len(expression.groups) - 1
			expression.groups[last] = append(expression.groups[last], token.condition)
		case "OR":
			expression.groups = append(expression.groups, []string{token.condition})
		default:
			return matchExpression{}, fmt.Errorf("不支持的匹配运算符 %q", token.operator)
		}
	}
	return expression, nil
}

func tokenizeMatchRule(rule string) ([]matchToken, error) {
	var tokens []matchToken
	var condition strings.Builder
	pendingOperator := ""

	flush := func(operator string) error {
		value := strings.TrimSpace(condition.String())
		if value == "" {
			if len(tokens) == 0 {
				return fmt.Errorf("运算符 %s 前缺少匹配条件", operator)
			}
			return fmt.Errorf("运算符 %s 前存在空条件", operator)
		}
		tokens = append(tokens, matchToken{condition: value, operator: pendingOperator})
		condition.Reset()
		pendingOperator = operator
		return nil
	}

	for i := 0; i < len(rule); {
		if op, width := symbolicMatchOperator(rule, i); op != "" {
			if err := flush(op); err != nil {
				return nil, err
			}
			i += width
			continue
		}
		if op, width := textualMatchOperator(rule, i); op != "" {
			if err := flush(op); err != nil {
				return nil, err
			}
			i += width
			continue
		}

		r, width := utf8.DecodeRuneInString(rule[i:])
		condition.WriteRune(r)
		i += width
	}

	last := strings.TrimSpace(condition.String())
	if last == "" {
		if pendingOperator != "" {
			return nil, fmt.Errorf("运算符 %s 后缺少匹配条件", pendingOperator)
		}
		return nil, fmt.Errorf("匹配规则不能为空")
	}
	tokens = append(tokens, matchToken{condition: last, operator: pendingOperator})
	return tokens, nil
}

func symbolicMatchOperator(rule string, index int) (string, int) {
	if index+2 > len(rule) {
		return "", 0
	}
	raw := rule[index : index+2]
	var op string
	switch raw {
	case "&&":
		op = "AND"
	case "||":
		op = "OR"
	default:
		return "", 0
	}

	// Whitespace-delimited symbols are always operators. Without whitespace,
	// require the right side to start with a typed condition. This preserves
	// useful regex/body payloads such as regex:foo||bar while accepting compact
	// rules such as status:200||status:302.
	leftSpace := index > 0 && previousRuneIsSpace(rule[:index])
	rightSpace := index+2 < len(rule) && nextRuneIsSpace(rule[index+2:])
	if leftSpace || rightSpace || startsTypedMatchCondition(rule[index+2:]) {
		return op, 2
	}
	return "", 0
}

func textualMatchOperator(rule string, index int) (string, int) {
	aliases := []struct {
		text string
		op   string
	}{
		{"AND", "AND"},
		{"OR", "OR"},
		{"和", "AND"},
		{"或", "OR"},
	}

	for _, alias := range aliases {
		if index+len(alias.text) > len(rule) || !strings.EqualFold(rule[index:index+len(alias.text)], alias.text) {
			continue
		}
		leftBoundary := index == 0 || previousRuneIsSpace(rule[:index])
		rightIndex := index + len(alias.text)
		rightBoundary := rightIndex == len(rule) || nextRuneIsSpace(rule[rightIndex:])
		if leftBoundary && rightBoundary {
			return alias.op, len(alias.text)
		}
	}
	return "", 0
}

func previousRuneIsSpace(value string) bool {
	r, _ := utf8.DecodeLastRuneInString(value)
	return unicode.IsSpace(r)
}

func nextRuneIsSpace(value string) bool {
	r, _ := utf8.DecodeRuneInString(value)
	return unicode.IsSpace(r)
}

func startsTypedMatchCondition(value string) bool {
	lower := strings.ToLower(strings.TrimLeftFunc(value, unicode.IsSpace))
	return strings.HasPrefix(lower, "status:") ||
		strings.HasPrefix(lower, "header:") ||
		strings.HasPrefix(lower, "body:") ||
		strings.HasPrefix(lower, "regex:") ||
		strings.HasPrefix(lower, "duration:") ||
		strings.HasPrefix(lower, "time:") ||
		strings.HasPrefix(lower, "elapsed:") ||
		strings.HasPrefix(lower, "timeout:")
}

func validateMatchCondition(condition string) error {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return fmt.Errorf("匹配条件不能为空")
	}

	lower := strings.ToLower(condition)
	switch {
	case strings.HasPrefix(lower, "status:"):
		_, _, err := matchStatus(200, strings.TrimSpace(condition[len("status:"):]))
		return err
	case strings.HasPrefix(lower, "header:"):
		parts := strings.SplitN(strings.TrimSpace(condition[len("header:"):]), "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			return fmt.Errorf("header 规则应为 header:Key=Value")
		}
	case strings.HasPrefix(lower, "body:"):
		if strings.TrimSpace(condition[len("body:"):]) == "" {
			return fmt.Errorf("body 规则不能为空")
		}
	case strings.HasPrefix(lower, "regex:"):
		pattern := strings.TrimSpace(condition[len("regex:"):])
		if pattern == "" {
			return fmt.Errorf("regex 规则不能为空")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("无效正则表达式: %w", err)
		}
	case hasDurationPrefix(lower):
		_, _, err := parseDurationCondition(durationConditionValue(condition))
		return err
	case strings.HasPrefix(lower, "timeout:"):
		_, err := parseBooleanCondition(strings.TrimSpace(condition[len("timeout:"):]))
		return err
	}
	return nil
}

func hasDurationPrefix(lower string) bool {
	return strings.HasPrefix(lower, "duration:") || strings.HasPrefix(lower, "time:") || strings.HasPrefix(lower, "elapsed:")
}

func durationConditionValue(condition string) string {
	lower := strings.ToLower(condition)
	for _, prefix := range []string{"duration:", "elapsed:", "time:"} {
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSpace(condition[len(prefix):])
		}
	}
	return ""
}

func parseDurationCondition(raw string) (string, time.Duration, error) {
	value := strings.TrimSpace(raw)
	operator := ">="
	for _, candidate := range []string{">=", "<=", "==", ">", "<", "="} {
		if strings.HasPrefix(value, candidate) {
			operator = candidate
			value = strings.TrimSpace(value[len(candidate):])
			break
		}
	}
	if value == "" {
		return "", 0, fmt.Errorf("duration 规则不能为空，例如 duration:>=5s")
	}
	threshold, err := time.ParseDuration(value)
	if err != nil {
		return "", 0, fmt.Errorf("无效耗时阈值 %q，请使用 500ms、3s、1m 等格式", value)
	}
	if threshold <= 0 {
		return "", 0, fmt.Errorf("耗时阈值必须大于 0")
	}
	return operator, threshold, nil
}

func parseBooleanCondition(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "yes", "1", "是":
		return true, nil
	case "false", "no", "0", "否":
		return false, nil
	default:
		return false, fmt.Errorf("timeout 规则应为 timeout:true 或 timeout:false")
	}
}

func evaluateMatchCondition(context matchContext, condition string) (bool, string, error) {
	condition = strings.TrimSpace(condition)
	if err := validateMatchCondition(condition); err != nil {
		return false, "", err
	}

	lower := strings.ToLower(condition)
	switch {
	case strings.HasPrefix(lower, "timeout:"):
		expected, _ := parseBooleanCondition(strings.TrimSpace(condition[len("timeout:"):]))
		if context.timedOut == expected {
			if expected {
				return true, fmt.Sprintf("请求在 %s 后达到超时阈值", formatMatchDuration(context.duration)), nil
			}
			return true, "请求在超时阈值内完成", nil
		}
		if expected {
			return false, fmt.Sprintf("请求在 %s 内完成，未触发超时", formatMatchDuration(context.duration)), nil
		}
		return false, fmt.Sprintf("请求在 %s 后超时", formatMatchDuration(context.duration)), nil
	case hasDurationPrefix(lower):
		operator, threshold, _ := parseDurationCondition(durationConditionValue(condition))
		matched := compareDuration(context.duration, operator, threshold)
		reason := fmt.Sprintf("响应耗时 %s %s 阈值 %s", formatMatchDuration(context.duration), comparisonText(operator), threshold)
		if !matched {
			reason = fmt.Sprintf("响应耗时 %s 未满足 %s %s", formatMatchDuration(context.duration), comparisonText(operator), threshold)
		}
		return matched, reason, nil
	case strings.HasPrefix(lower, "status:"):
		if context.response == nil {
			return false, "未获得 HTTP 响应，无法判定状态码", nil
		}
		return matchStatus(context.response.StatusCode, strings.TrimSpace(condition[len("status:"):]))
	case strings.HasPrefix(lower, "header:"):
		if context.response == nil {
			return false, "未获得 HTTP 响应，无法判定响应头", nil
		}
		return matchHeader(context.response, strings.TrimSpace(condition[len("header:"):]))
	case strings.HasPrefix(lower, "body:"):
		if context.response == nil {
			return false, "未获得 HTTP 响应，无法判定响应体", nil
		}
		expected := strings.TrimSpace(condition[len("body:"):])
		if strings.Contains(context.body, expected) {
			return true, fmt.Sprintf("响应体包含 %q", expected), nil
		}
		return false, fmt.Sprintf("响应体不包含 %q", expected), nil
	case strings.HasPrefix(lower, "regex:"):
		if context.response == nil {
			return false, "未获得 HTTP 响应，无法执行响应体正则", nil
		}
		pattern := strings.TrimSpace(condition[len("regex:"):])
		matcher, err := regexp.Compile(pattern)
		if err != nil {
			return false, "", err
		}
		if matcher.MatchString(context.body) {
			return true, fmt.Sprintf("响应体正则 %q 命中", pattern), nil
		}
		return false, fmt.Sprintf("响应体正则 %q 未命中", pattern), nil
	default:
		if context.response == nil {
			return false, "未获得 HTTP 响应，无法判定响应体文本", nil
		}
		if strings.Contains(context.body, condition) {
			return true, fmt.Sprintf("响应体包含 %q", condition), nil
		}
		return false, fmt.Sprintf("响应体不包含 %q", condition), nil
	}
}

func compareDuration(actual time.Duration, operator string, threshold time.Duration) bool {
	switch operator {
	case ">=":
		return actual >= threshold
	case "<=":
		return actual <= threshold
	case ">":
		return actual > threshold
	case "<":
		return actual < threshold
	case "=", "==":
		return actual == threshold
	default:
		return false
	}
}

func comparisonText(operator string) string {
	switch operator {
	case ">=":
		return "≥"
	case "<=":
		return "≤"
	default:
		return operator
	}
}

func formatMatchDuration(duration time.Duration) string {
	if duration <= 0 {
		return "0s"
	}
	return duration.Round(time.Millisecond).String()
}

func (expression matchExpression) evaluate(context matchContext) (bool, string, error) {
	type groupResult struct {
		matched bool
		lines   []string
	}
	results := make([]groupResult, 0, len(expression.groups))
	matchedGroup := 0

	for groupIndex, group := range expression.groups {
		result := groupResult{matched: true, lines: make([]string, 0, len(group))}
		for _, condition := range group {
			matched, reason, err := evaluateMatchCondition(context, condition)
			if err != nil {
				return false, "", err
			}
			mark := "✓"
			if !matched {
				mark = "✗"
				result.matched = false
			}
			result.lines = append(result.lines, fmt.Sprintf("%s %s", mark, reason))
		}
		if result.matched && matchedGroup == 0 {
			matchedGroup = groupIndex + 1
		}
		results = append(results, result)
	}

	matched := matchedGroup > 0
	if len(results) == 1 {
		title := "条件未成立"
		if matched {
			title = "条件成立"
		}
		if len(results[0].lines) > 1 {
			title = "AND " + title
		}
		return matched, title + "\n" + strings.Join(results[0].lines, "\n"), nil
	}

	title := fmt.Sprintf("OR 条件未成立（0/%d 个分支命中）", len(results))
	if matched {
		title = fmt.Sprintf("OR 条件成立（命中分支 %d/%d）", matchedGroup, len(results))
	}
	sections := []string{title}
	for index, result := range results {
		state := "未命中"
		if result.matched {
			state = "已命中"
		}
		sections = append(sections, fmt.Sprintf("分支 %d · %s\n%s", index+1, state, strings.Join(result.lines, "\n")))
	}
	return matched, strings.Join(sections, "\n"), nil
}
