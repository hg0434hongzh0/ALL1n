package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type RunSettings struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
}

type StepResult struct {
	Index      int
	Name       string
	Method     string
	Path       string
	URL        string
	StatusCode int
	Duration   time.Duration
	Level      string
	Message    string
}

type ExploitResult struct {
	POCName     string
	Method      string
	Path        string
	URL         string
	StatusCode  int
	Duration    time.Duration
	Level       string
	Message     string
	StepResults []StepResult
}

type Runner struct {
	secureTransport   *http.Transport
	insecureTransport *http.Transport
}

type runState struct {
	vars        map[string]string
	lastBody    string
	lastURL     string
	lastStatus  int
	lastHeaders http.Header
}

type stepRunOutcome struct {
	Result          StepResult
	ResponseHeaders http.Header
	ResponseBody    string
	Matched         bool
	MatchConfigured bool
}

func NewRunner() *Runner {
	secureTransport := http.DefaultTransport.(*http.Transport).Clone()
	insecureTransport := http.DefaultTransport.(*http.Transport).Clone()
	insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	return &Runner{
		secureTransport:   secureTransport,
		insecureTransport: insecureTransport,
	}
}

func (r *Runner) Run(targetBase string, poc *POC, settings RunSettings) ExploitResult {
	result := ExploitResult{}
	if poc == nil {
		result.Level = "ERR"
		result.Message = "POC 数据为空"
		return result
	}

	poc = clonePOC(poc)
	poc.normalize()

	result.POCName = poc.Name
	if settings.Timeout <= 0 {
		settings.Timeout = 10 * time.Second
	}

	client, err := r.newClient(settings)
	if err != nil {
		result.Level = "ERR"
		result.Message = fmt.Sprintf("[%s] 初始化客户端失败: %v", poc.Name, err)
		return result
	}

	state := newRunState(targetBase)
	startedAt := time.Now()
	requiredMatches := 0

	for index, rawStep := range poc.normalizedSteps() {
		resolvedStep := renderStep(rawStep, state)
		outcome := r.runStep(client, targetBase, poc.Name, resolvedStep, index, settings)
		result.StepResults = append(result.StepResults, outcome.Result)

		if outcome.Result.StatusCode != 0 {
			result.StatusCode = outcome.Result.StatusCode
		}
		if outcome.Result.URL != "" {
			result.URL = outcome.Result.URL
		}
		result.Method = outcome.Result.Method
		result.Path = outcome.Result.Path

		if outcome.Result.Level == "ERR" {
			result.Level = "ERR"
			result.Duration = time.Since(startedAt)
			result.Message = fmt.Sprintf("[!] %s 在步骤 %d 失败：%s", poc.Name, index+1, outcome.Result.Message)
			if !resolvedStep.ContinueOnError {
				return result
			}
			continue
		}

		state.updateFromResponse(outcome.Result.URL, outcome.Result.StatusCode, outcome.ResponseHeaders, outcome.ResponseBody)
		if extractErr := applyExtractRules(&resolvedStep, state, outcome.ResponseHeaders, outcome.ResponseBody, outcome.Result.StatusCode); extractErr != nil {
			result.Level = "ERR"
			result.Duration = time.Since(startedAt)
			result.Message = fmt.Sprintf("[!] %s 提取变量失败：%v", poc.Name, extractErr)
			return result
		}

		if outcome.MatchConfigured {
			requiredMatches++
			if !outcome.Matched {
				result.Level = "SAFE"
				result.Duration = time.Since(startedAt)
				result.Message = fmt.Sprintf("[-] %s 在步骤 %d 未满足匹配规则", poc.Name, index+1)
				if !resolvedStep.ContinueOnError {
					return result
				}
			}
		}
	}

	result.Duration = time.Since(startedAt)
	switch {
	case result.Level == "ERR":
		return result
	case requiredMatches > 0:
		result.Level = "VULN"
		result.Message = fmt.Sprintf("[+] %s 链式验证完成，全部关键步骤命中", poc.Name)
	default:
		result.Level = "SAFE"
		result.Message = fmt.Sprintf("[-] %s 链式请求已执行，但未配置命中规则", poc.Name)
	}
	return result
}

func (r *Runner) newClient(settings RunSettings) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	transport := r.secureTransport
	if settings.InsecureSkipVerify {
		transport = r.insecureTransport
	}

	return &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   settings.Timeout,
	}, nil
}

func (r *Runner) runStep(client *http.Client, targetBase, pocName string, step RequestStep, index int, settings RunSettings) stepRunOutcome {
	outcome := stepRunOutcome{
		Result: StepResult{
			Index:  index,
			Name:   step.Name,
			Method: step.Method,
			Path:   step.Path,
		},
	}

	startedAt := time.Now()
	fullURL, err := buildTargetURL(targetBase, step.Path, step.Params)
	if err != nil {
		outcome.Result.Level = "ERR"
		outcome.Result.Message = fmt.Sprintf("[%s / %s] URL 构造失败: %v", pocName, step.Name, err)
		return outcome
	}

	outcome.Result.URL = fullURL
	var bodyReader io.Reader
	if step.Method != http.MethodGet && strings.TrimSpace(step.Body) != "" {
		bodyReader = strings.NewReader(step.Body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), settings.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, step.Method, fullURL, bodyReader)
	if err != nil {
		outcome.Result.Level = "ERR"
		outcome.Result.Message = fmt.Sprintf("[%s / %s] 请求构造失败: %v", pocName, step.Name, err)
		return outcome
	}

	applyStepHeaders(req, step)

	resp, err := client.Do(req)
	if err != nil {
		outcome.Result.Level = "ERR"
		outcome.Result.Duration = time.Since(startedAt)
		outcome.Result.Message = fmt.Sprintf("[%s / %s] 请求失败: %v", pocName, step.Name, err)
		return outcome
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		outcome.Result.Level = "ERR"
		outcome.Result.Duration = time.Since(startedAt)
		outcome.Result.Message = fmt.Sprintf("[%s / %s] 读取响应失败: %v", pocName, step.Name, err)
		return outcome
	}

	outcome.ResponseBody = string(respBody)
	outcome.ResponseHeaders = resp.Header.Clone()
	outcome.Result.StatusCode = resp.StatusCode
	outcome.Result.Duration = time.Since(startedAt)

	if strings.TrimSpace(step.MatchRule) == "" {
		outcome.Result.Level = "INFO"
		outcome.Result.Message = fmt.Sprintf("[步骤 %d] %s 执行完成 [HTTP %d, %s]", index+1, step.Name, resp.StatusCode, outcome.Result.Duration.Round(time.Millisecond))
		return outcome
	}

	outcome.MatchConfigured = true
	matched, reason, err := evaluateMatch(resp, outcome.ResponseBody, step.MatchRule)
	if err != nil {
		outcome.Result.Level = "ERR"
		outcome.Result.Message = fmt.Sprintf("[%s / %s] 匹配规则错误: %v", pocName, step.Name, err)
		return outcome
	}

	outcome.Matched = matched
	if matched {
		outcome.Result.Level = "INFO"
		outcome.Result.Message = fmt.Sprintf("[步骤 %d] %s 命中规则（%s） [HTTP %d, %s]", index+1, step.Name, reason, resp.StatusCode, outcome.Result.Duration.Round(time.Millisecond))
		return outcome
	}

	outcome.Result.Level = "SAFE"
	outcome.Result.Message = fmt.Sprintf("[步骤 %d] %s 未命中规则（%s） [HTTP %d, %s]", index+1, step.Name, reason, resp.StatusCode, outcome.Result.Duration.Round(time.Millisecond))
	return outcome
}

func buildTargetURL(targetBase, stepPath, rawParams string) (string, error) {
	base := strings.TrimSpace(targetBase)
	if base == "" {
		return "", fmt.Errorf("目标地址为空")
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}

	cleanPath := strings.TrimSpace(stepPath)
	if cleanPath == "" {
		cleanPath = "/"
	}

	var parsedURL *url.URL
	var err error
	if parsedAbsolute, absoluteErr := url.Parse(cleanPath); absoluteErr == nil && parsedAbsolute.IsAbs() {
		parsedURL = parsedAbsolute
	} else {
		parsedURL, err = url.Parse(base)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(cleanPath, "/") {
			cleanPath = "/" + cleanPath
		}
		parsedURL.Path = strings.TrimRight(parsedURL.Path, "/") + cleanPath
	}

	if strings.TrimSpace(rawParams) != "" {
		params, err := url.ParseQuery(rawParams)
		if err != nil {
			return "", fmt.Errorf("参数格式无效: %w", err)
		}

		query := parsedURL.Query()
		for key, values := range params {
			for _, value := range values {
				query.Add(key, value)
			}
		}
		parsedURL.RawQuery = query.Encode()
	}

	return parsedURL.String(), nil
}

func applyStepHeaders(req *http.Request, step RequestStep) {
	switch step.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		switch strings.TrimSpace(step.BodyType) {
		case "JSON":
			req.Header.Set("Content-Type", "application/json")
		case "Form":
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	req.Header.Set("User-Agent", "ALL1n-POC-Workbench/2.1")

	lines := strings.Split(step.Headers, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		headerKey := strings.TrimSpace(parts[0])
		headerValue := strings.TrimSpace(parts[1])
		if headerKey != "" {
			req.Header.Set(headerKey, headerValue)
		}
	}
}

func evaluateMatch(resp *http.Response, body, rule string) (bool, string, error) {
	trimmedRule := strings.TrimSpace(rule)
	if trimmedRule == "" {
		return false, "未配置匹配规则", nil
	}

	orGroups := splitTopLevel(trimmedRule, "||")
	failReasons := make([]string, 0, len(orGroups))

	for _, group := range orGroups {
		group = trimOuterParentheses(group)
		if group == "" {
			continue
		}

		andExpressions := splitTopLevel(group, "&&")
		groupReasons := make([]string, 0, len(andExpressions))
		groupMatched := true

		for _, expression := range andExpressions {
			ok, reason, err := evaluateAtomicMatch(resp, body, expression)
			if err != nil {
				return false, "", err
			}
			if !ok {
				groupMatched = false
				failReasons = append(failReasons, reason)
				break
			}
			groupReasons = append(groupReasons, reason)
		}

		if groupMatched {
			return true, strings.Join(groupReasons, " && "), nil
		}
	}

	if len(failReasons) == 0 {
		return false, "未配置有效匹配规则", nil
	}

	return false, strings.Join(failReasons, " || "), nil
}

func evaluateAtomicMatch(resp *http.Response, body, expression string) (bool, string, error) {
	expression = trimOuterParentheses(strings.TrimSpace(expression))
	if expression == "" {
		return true, "空规则", nil
	}

	negated := strings.HasPrefix(expression, "!")
	if negated {
		expression = trimOuterParentheses(strings.TrimSpace(strings.TrimPrefix(expression, "!")))
	}

	ok, reason, err := evaluatePositiveMatch(resp, body, expression)
	if err != nil {
		return false, "", err
	}
	if !negated {
		return ok, reason, nil
	}
	if ok {
		return false, "取反失败：" + reason, nil
	}
	return true, "取反命中：" + reason, nil
}

func evaluatePositiveMatch(resp *http.Response, body, expression string) (bool, string, error) {
	lowerExpr := strings.ToLower(expression)
	switch {
	case strings.HasPrefix(lowerExpr, "status:"):
		return matchStatus(resp.StatusCode, strings.TrimSpace(expression[len("status:"):]))
	case strings.HasPrefix(lowerExpr, "header:"):
		return matchHeader(resp, strings.TrimSpace(expression[len("header:"):]))
	case strings.HasPrefix(lowerExpr, "headers:"):
		needle := strings.TrimSpace(expression[len("headers:"):])
		headersText := flattenHeaders(resp.Header)
		if strings.Contains(strings.ToLower(headersText), strings.ToLower(needle)) {
			return true, fmt.Sprintf("headers 包含 %q", needle), nil
		}
		return false, fmt.Sprintf("headers 不包含 %q", needle), nil
	case strings.HasPrefix(lowerExpr, "body:"):
		needle := strings.TrimSpace(expression[len("body:"):])
		if strings.Contains(body, needle) {
			return true, fmt.Sprintf("body 包含 %q", needle), nil
		}
		return false, fmt.Sprintf("body 不包含 %q", needle), nil
	case strings.HasPrefix(lowerExpr, "regex:"):
		pattern := strings.TrimSpace(expression[len("regex:"):])
		matcher, err := regexp.Compile(pattern)
		if err != nil {
			return false, "", err
		}
		if matcher.MatchString(body) {
			return true, fmt.Sprintf("regex %q", pattern), nil
		}
		return false, fmt.Sprintf("regex %q 未命中", pattern), nil
	default:
		if strings.Contains(body, expression) {
			return true, fmt.Sprintf("正文包含 %q", expression), nil
		}
		return false, fmt.Sprintf("正文不包含 %q", expression), nil
	}
}

func matchStatus(statusCode int, rawRule string) (bool, string, error) {
	rule := strings.TrimSpace(strings.ToLower(rawRule))
	if rule == "" {
		return false, "", fmt.Errorf("status 规则不能为空")
	}

	if strings.HasSuffix(rule, "xx") && len(rule) == 3 {
		prefix, err := strconv.Atoi(string(rule[0]))
		if err != nil {
			return false, "", err
		}
		if statusCode/100 == prefix {
			return true, fmt.Sprintf("status 属于 %s", strings.ToUpper(rule)), nil
		}
		return false, fmt.Sprintf("status 不属于 %s", strings.ToUpper(rule)), nil
	}

	if strings.Contains(rule, "-") {
		parts := strings.SplitN(rule, "-", 2)
		if len(parts) != 2 {
			return false, "", fmt.Errorf("status 范围规则无效: %s", rawRule)
		}

		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return false, "", err
		}
		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return false, "", err
		}

		if statusCode >= start && statusCode <= end {
			return true, fmt.Sprintf("status 命中 %d-%d", start, end), nil
		}
		return false, fmt.Sprintf("status 未命中 %d-%d", start, end), nil
	}

	expectedStatus, err := strconv.Atoi(rule)
	if err != nil {
		return false, "", err
	}
	if statusCode == expectedStatus {
		return true, fmt.Sprintf("status 等于 %d", expectedStatus), nil
	}
	return false, fmt.Sprintf("status 不等于 %d", expectedStatus), nil
}

func matchHeader(resp *http.Response, rawRule string) (bool, string, error) {
	parts := strings.SplitN(rawRule, "=", 2)
	if len(parts) != 2 {
		return false, "", fmt.Errorf("header 规则应为 header:Key=Value")
	}

	headerKey := strings.TrimSpace(parts[0])
	expectedValue := strings.TrimSpace(parts[1])
	if headerKey == "" {
		return false, "", fmt.Errorf("header 名称不能为空")
	}

	currentValue := resp.Header.Get(headerKey)
	if strings.Contains(strings.ToLower(currentValue), strings.ToLower(expectedValue)) {
		return true, fmt.Sprintf("header %s 包含 %q", headerKey, expectedValue), nil
	}

	return false, fmt.Sprintf("header %s 未包含 %q", headerKey, expectedValue), nil
}

func newRunState(targetBase string) *runState {
	base := strings.TrimSpace(targetBase)
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}

	parsed, _ := url.Parse(base)
	rootURL := ""
	host := ""
	hostname := ""
	port := ""
	scheme := ""
	if parsed != nil {
		rootURL = parsed.Scheme + "://" + parsed.Host
		host = parsed.Host
		hostname = parsed.Hostname()
		port = parsed.Port()
		scheme = parsed.Scheme
	}

	vars := map[string]string{
		"target":   base,
		"base_url": base,
		"BaseURL":  base,
		"RootURL":  rootURL,
		"Host":     host,
		"Hostname": hostname,
		"Port":     port,
		"Scheme":   scheme,
	}

	return &runState{
		vars:        vars,
		lastHeaders: make(http.Header),
	}
}

func (s *runState) updateFromResponse(fullURL string, statusCode int, headers http.Header, body string) {
	s.lastURL = fullURL
	s.lastStatus = statusCode
	s.lastHeaders = headers.Clone()
	s.lastBody = body
	s.vars["last_url"] = fullURL
	s.vars["last_status"] = strconv.Itoa(statusCode)
	s.vars["last_body"] = body
}

func renderStep(step RequestStep, state *runState) RequestStep {
	step.Name = renderTemplate(step.Name, state)
	step.Method = strings.ToUpper(strings.TrimSpace(renderTemplate(step.Method, state)))
	step.Path = renderTemplate(step.Path, state)
	step.Params = renderTemplate(step.Params, state)
	step.Body = renderTemplate(step.Body, state)
	step.Headers = renderTemplate(step.Headers, state)
	step.MatchRule = renderTemplate(step.MatchRule, state)
	step.ExtractRules = renderTemplate(step.ExtractRules, state)
	step.normalize(0)
	return step
}

var templatePattern = regexp.MustCompile(`\{\{\s*([^{}]+?)\s*\}\}`)

func renderTemplate(input string, state *runState) string {
	if state == nil || input == "" {
		return input
	}

	return templatePattern.ReplaceAllStringFunc(input, func(token string) string {
		matches := templatePattern.FindStringSubmatch(token)
		if len(matches) != 2 {
			return token
		}

		key := strings.TrimSpace(matches[1])
		switch {
		case strings.HasPrefix(strings.ToLower(key), "last_header:"):
			headerName := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(key[len("last_header:"):]))
			if headerName == "" {
				return token
			}
			return state.lastHeaders.Get(headerName)
		case strings.HasPrefix(strings.ToLower(key), "header:"):
			headerName := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(key[len("header:"):]))
			if headerName == "" {
				return token
			}
			return state.lastHeaders.Get(headerName)
		}

		if value, ok := state.vars[key]; ok {
			return value
		}
		if value, ok := state.vars[strings.ToLower(key)]; ok {
			return value
		}
		return token
	})
}

func applyExtractRules(step *RequestStep, state *runState, headers http.Header, body string, statusCode int) error {
	if step == nil || state == nil || strings.TrimSpace(step.ExtractRules) == "" {
		return nil
	}

	lines := strings.Split(step.ExtractRules, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("提取规则无效: %s", line)
		}

		key := strings.TrimSpace(parts[0])
		rule := strings.TrimSpace(parts[1])
		if key == "" || rule == "" {
			return fmt.Errorf("提取规则无效: %s", line)
		}

		value, err := extractValue(rule, headers, body, statusCode)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		state.vars[key] = value
		state.vars[strings.ToLower(key)] = value
	}

	return nil
}

func extractValue(rule string, headers http.Header, body string, statusCode int) (string, error) {
	lowerRule := strings.ToLower(rule)
	switch {
	case lowerRule == "body":
		return body, nil
	case lowerRule == "status":
		return strconv.Itoa(statusCode), nil
	case strings.HasPrefix(lowerRule, "body_regex:"):
		pattern := strings.TrimSpace(rule[len("body_regex:"):])
		return extractByRegex(pattern, body)
	case strings.HasPrefix(lowerRule, "headers_regex:"):
		pattern := strings.TrimSpace(rule[len("headers_regex:"):])
		return extractByRegex(pattern, flattenHeaders(headers))
	case strings.HasPrefix(lowerRule, "header_regex:"):
		raw := strings.TrimSpace(rule[len("header_regex:"):])
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("header_regex 规则应为 header_regex:Header:Pattern")
		}
		headerName := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(parts[0]))
		return extractByRegex(strings.TrimSpace(parts[1]), headers.Get(headerName))
	case strings.HasPrefix(lowerRule, "header:"):
		headerName := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(rule[len("header:"):]))
		if headerName == "" {
			return "", fmt.Errorf("header 名称不能为空")
		}
		return headers.Get(headerName), nil
	default:
		return "", fmt.Errorf("不支持的提取规则: %s", rule)
	}
}

func extractByRegex(pattern, source string) (string, error) {
	matcher, err := regexp.Compile(pattern)
	if err != nil {
		return "", err
	}

	matches := matcher.FindStringSubmatch(source)
	if len(matches) == 0 {
		return "", fmt.Errorf("正则未命中")
	}
	if len(matches) > 1 {
		return matches[1], nil
	}
	return matches[0], nil
}

func flattenHeaders(headers http.Header) string {
	if len(headers) == 0 {
		return ""
	}

	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, key+": "+strings.Join(headers.Values(key), ", "))
	}
	return strings.Join(lines, "\n")
}

func splitTopLevel(input, separator string) []string {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}

	var parts []string
	start := 0
	depth := 0
	for i := 0; i < len(input); i++ {
		switch input[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}

		if depth == 0 && strings.HasPrefix(input[i:], separator) {
			part := strings.TrimSpace(input[start:i])
			if part != "" {
				parts = append(parts, part)
			}
			i += len(separator) - 1
			start = i + 1
		}
	}

	last := strings.TrimSpace(input[start:])
	if last != "" {
		parts = append(parts, last)
	}
	return parts
}

func trimOuterParentheses(input string) string {
	input = strings.TrimSpace(input)
	for strings.HasPrefix(input, "(") && strings.HasSuffix(input, ")") {
		depth := 0
		valid := true
		for i := 0; i < len(input); i++ {
			switch input[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 && i < len(input)-1 {
					valid = false
				}
			}
			if depth < 0 {
				valid = false
				break
			}
		}
		if !valid || depth != 0 {
			break
		}
		input = strings.TrimSpace(input[1 : len(input)-1])
	}
	return input
}
