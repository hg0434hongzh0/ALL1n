package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type nucleiTemplate struct {
	ID       string              `yaml:"id"`
	Info     nucleiTemplateInfo  `yaml:"info"`
	HTTP     []nucleiHTTPRequest `yaml:"http"`
	Requests []nucleiHTTPRequest `yaml:"requests"`
}

type nucleiTemplateInfo struct {
	Name        string   `yaml:"name"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
}

type nucleiHTTPRequest struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	Raw               []string          `yaml:"raw"`
	Body              string            `yaml:"body"`
	Headers           map[string]string `yaml:"headers"`
	Matchers          []nucleiMatcher   `yaml:"matchers"`
	MatchersCondition string            `yaml:"matchers-condition"`
	Extractors        []nucleiExtractor `yaml:"extractors"`
}

type nucleiMatcher struct {
	Name      string   `yaml:"name"`
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Status    []int    `yaml:"status"`
	Condition string   `yaml:"condition"`
	Negative  bool     `yaml:"negative"`
}

type nucleiExtractor struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Part     string   `yaml:"part"`
	Regex    []string `yaml:"regex"`
	KVal     []string `yaml:"kval"`
	Internal bool     `yaml:"internal"`
}

func importNucleiTemplate(reader io.Reader) (string, []POC, error) {
	payload, err := io.ReadAll(reader)
	if err != nil {
		return "", nil, err
	}

	var tpl nucleiTemplate
	if err := yaml.Unmarshal(payload, &tpl); err != nil {
		return "", nil, err
	}

	pocs, err := convertNucleiTemplate(tpl)
	if err != nil {
		return "", nil, err
	}

	folderName := strings.TrimSpace(tpl.Info.Name)
	if folderName == "" {
		folderName = strings.TrimSpace(tpl.ID)
	}
	if folderName == "" {
		folderName = "Nuclei 导入"
	}
	if strings.TrimSpace(tpl.Info.Severity) != "" {
		folderName = fmt.Sprintf("%s [%s]", folderName, strings.ToUpper(strings.TrimSpace(tpl.Info.Severity)))
	}

	return folderName, pocs, nil
}

func convertNucleiTemplate(tpl nucleiTemplate) ([]POC, error) {
	requests := tpl.HTTP
	if len(requests) == 0 {
		requests = tpl.Requests
	}
	if len(requests) == 0 {
		return nil, fmt.Errorf("模板中未找到 http/requests 段")
	}

	baseName := strings.TrimSpace(tpl.Info.Name)
	if baseName == "" {
		baseName = strings.TrimSpace(tpl.ID)
	}
	if baseName == "" {
		baseName = "Nuclei 模板"
	}

	if len(requests) == 1 && len(requests[0].Raw) == 0 && len(requests[0].Path) > 1 {
		pocs := make([]POC, 0, len(requests[0].Path))
		for index, rawPath := range requests[0].Path {
			req := requests[0]
			req.Path = []string{rawPath}

			step, err := nucleiRequestToStep(req, 0)
			if err != nil {
				return nil, err
			}

			poc := POC{
				Name:  fmt.Sprintf("%s [%d]", baseName, index+1),
				Steps: []RequestStep{step},
			}
			poc.normalize()
			pocs = append(pocs, poc)
		}
		return pocs, nil
	}

	if len(requests) == 1 && len(requests[0].Path) == 0 && len(requests[0].Raw) > 1 {
		pocs := make([]POC, 0, len(requests[0].Raw))
		for index, rawRequest := range requests[0].Raw {
			req := requests[0]
			req.Raw = []string{rawRequest}

			step, err := nucleiRequestToStep(req, 0)
			if err != nil {
				return nil, err
			}

			poc := POC{
				Name:  fmt.Sprintf("%s [raw-%d]", baseName, index+1),
				Steps: []RequestStep{step},
			}
			poc.normalize()
			pocs = append(pocs, poc)
		}
		return pocs, nil
	}

	steps := make([]RequestStep, 0, len(requests))
	for index, req := range requests {
		step, err := nucleiRequestToStep(req, index)
		if err != nil {
			return nil, err
		}
		steps = append(steps, step)
	}

	poc := POC{
		Name:  baseName,
		Steps: steps,
	}
	poc.normalize()
	return []POC{poc}, nil
}

func nucleiRequestToStep(req nucleiHTTPRequest, index int) (RequestStep, error) {
	step := defaultRequestStep(fmt.Sprintf("步骤 %d", index+1))

	if len(req.Raw) > 0 {
		method, path, headers, body, err := parseRawHTTPRequest(req.Raw[0])
		if err != nil {
			return step, err
		}
		step.Method = method
		step.Path = path
		step.Headers = headers
		step.Body = body
	} else {
		step.Method = valueOr(strings.ToUpper(strings.TrimSpace(req.Method)), "GET")
		if len(req.Path) > 0 {
			step.Path = req.Path[0]
		}
		if len(req.Headers) > 0 {
			step.Headers = formatHeaderMap(req.Headers)
		}
		step.Body = req.Body
	}

	if matcherRule := nucleiMatchersToRule(req.Matchers, req.MatchersCondition); matcherRule != "" {
		step.MatchRule = matcherRule
	}
	if extractRule := nucleiExtractorsToRules(req.Extractors); extractRule != "" {
		step.ExtractRules = extractRule
	}
	if looksLikeJSON(step.Body) {
		step.BodyType = "JSON"
	} else if strings.Contains(step.Body, "=") && strings.Contains(step.Body, "&") {
		step.BodyType = "Form"
	}

	step.normalize(index)
	return step, nil
}

func parseRawHTTPRequest(raw string) (method, path, headers, body string, err error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return "", "", "", "", fmt.Errorf("raw 请求为空")
	}

	requestLine := strings.Fields(lines[0])
	if len(requestLine) < 2 {
		return "", "", "", "", fmt.Errorf("raw 请求首行无效")
	}

	method = strings.ToUpper(requestLine[0])
	path = requestLine[1]

	headerLines := make([]string, 0)
	bodyStart := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			bodyStart = i + 1
			break
		}
		headerLines = append(headerLines, lines[i])
	}
	headers = strings.Join(headerLines, "\n")
	if bodyStart >= 0 && bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\n")
	}

	return method, path, headers, body, nil
}

func formatHeaderMap(headers map[string]string) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("%s: %s", key, headers[key]))
	}
	return strings.Join(lines, "\n")
}

func nucleiMatchersToRule(matchers []nucleiMatcher, globalCondition string) string {
	if len(matchers) == 0 {
		return ""
	}

	outerJoiner := " && "
	if strings.EqualFold(strings.TrimSpace(globalCondition), "or") {
		outerJoiner = " || "
	}

	parts := make([]string, 0, len(matchers))
	for _, matcher := range matchers {
		rule := nucleiMatcherToRule(matcher)
		if rule != "" {
			parts = append(parts, rule)
		}
	}

	return strings.Join(parts, outerJoiner)
}

func nucleiMatcherToRule(matcher nucleiMatcher) string {
	joiner := " && "
	if strings.EqualFold(strings.TrimSpace(matcher.Condition), "or") {
		joiner = " || "
	}

	part := strings.ToLower(strings.TrimSpace(matcher.Part))
	if part == "" {
		part = "body"
	}

	parts := make([]string, 0)
	switch strings.ToLower(strings.TrimSpace(matcher.Type)) {
	case "word":
		for _, word := range matcher.Words {
			if strings.TrimSpace(word) == "" {
				continue
			}
			switch part {
			case "header", "all_headers":
				parts = append(parts, maybeNegate("headers:"+word, matcher.Negative))
			default:
				parts = append(parts, maybeNegate("body:"+word, matcher.Negative))
			}
		}
	case "regex":
		for _, regexPattern := range matcher.Regex {
			if strings.TrimSpace(regexPattern) == "" {
				continue
			}
			switch part {
			case "header", "all_headers":
				parts = append(parts, maybeNegate("headers:"+regexPattern, matcher.Negative))
			default:
				parts = append(parts, maybeNegate("regex:"+regexPattern, matcher.Negative))
			}
		}
	case "status":
		for _, status := range matcher.Status {
			parts = append(parts, maybeNegate(fmt.Sprintf("status:%d", status), matcher.Negative))
		}
	}

	if len(parts) == 0 {
		return ""
	}

	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, joiner) + ")"
}

func nucleiExtractorsToRules(extractors []nucleiExtractor) string {
	lines := make([]string, 0)
	for index, extractor := range extractors {
		name := strings.TrimSpace(extractor.Name)
		if name == "" {
			name = fmt.Sprintf("extract_%d", index+1)
		}

		part := strings.ToLower(strings.TrimSpace(extractor.Part))
		if part == "" {
			part = "body"
		}

		switch strings.ToLower(strings.TrimSpace(extractor.Type)) {
		case "regex":
			if len(extractor.Regex) == 0 {
				continue
			}
			pattern := extractor.Regex[0]
			if part == "header" || part == "all_headers" {
				lines = append(lines, fmt.Sprintf("%s=headers_regex:%s", name, pattern))
			} else {
				lines = append(lines, fmt.Sprintf("%s=body_regex:%s", name, pattern))
			}
		case "kval":
			if len(extractor.KVal) == 0 {
				continue
			}
			headerName := extractor.KVal[0]
			lines = append(lines, fmt.Sprintf("%s=header:%s", name, headerName))
		}
	}
	return strings.Join(lines, "\n")
}

func maybeNegate(rule string, negative bool) string {
	if !negative {
		return rule
	}
	return "!" + rule
}

func looksLikeJSON(body string) bool {
	trimmed := strings.TrimSpace(body)
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}
