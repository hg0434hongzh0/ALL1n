package main

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type logEntry struct {
	Level   string
	Message string
	At      time.Time
}

type runSummary struct {
	Total  int
	Done   int
	Vuln   int
	Err    int
	Cancel int
}

func main() {
	data, dataFilePath, loadErr := loadAppData()

	if data == nil {
		data = defaultAppData()
	}

	runner := NewRunner()
	a := app.NewWithID("com.all1n.pocworkbench")
	selectedThemeID := normalizedOptionID(productThemeOptions, a.Preferences().StringWithFallback("appearance.theme", defaultThemeID), defaultThemeID)
	selectedFontID := normalizedOptionID(productFontOptions, a.Preferences().StringWithFallback("appearance.font", defaultFontID), defaultFontID)
	a.Settings().SetTheme(newProductTheme(selectedThemeID, selectedFontID))
	w := a.NewWindow("ALL1n " + appVersion + " - POC 验证工作台")
	w.Resize(fyne.NewSize(1540, 940))

	targetEntry := widget.NewMultiLineEntry()
	targetEntry.SetPlaceHolder("每行一个目标，例如：\nhttps://app.example.com\n192.168.1.10:8080\n# 支持使用 # 添加注释")
	targetEntry.Wrapping = fyne.TextWrapOff
	targetScroll := container.NewScroll(targetEntry)
	targetScroll.SetMinSize(fyne.NewSize(0, 132))
	targetCountLabel := widget.NewLabel("0 个目标")
	targetCountLabel.TextStyle = fyne.TextStyle{Bold: true}
	refreshTargetCount := func(raw string) {
		if strings.TrimSpace(raw) == "" {
			targetCountLabel.SetText("0 个目标")
			return
		}
		targets, err := parseTargets(raw)
		if err != nil {
			targetCountLabel.SetText("目标列表待校验")
			return
		}
		targetCountLabel.SetText(fmt.Sprintf("%d 个有效目标", len(targets)))
	}
	targetEntry.OnChanged = refreshTargetCount

	timeoutEntry := widget.NewEntry()
	timeoutEntry.SetText(a.Preferences().StringWithFallback("run.timeout_seconds", "10"))
	timeoutEntry.SetPlaceHolder("超时(秒)")
	timeoutEntry.OnChanged = func(value string) {
		a.Preferences().SetString("run.timeout_seconds", strings.TrimSpace(value))
	}

	concurrencySelect := widget.NewSelect([]string{"1", "2", "4", "8", "16"}, nil)
	preferredConcurrency := a.Preferences().StringWithFallback("run.concurrency", "4")
	if preferredConcurrency != "1" && preferredConcurrency != "2" && preferredConcurrency != "4" && preferredConcurrency != "8" && preferredConcurrency != "16" {
		preferredConcurrency = "4"
	}
	concurrencySelect.SetSelected(preferredConcurrency)
	concurrencySelect.OnChanged = func(value string) {
		a.Preferences().SetString("run.concurrency", value)
	}

	insecureTLSCheck := widget.NewCheck("忽略 TLS 证书错误", func(value bool) {
		a.Preferences().SetBool("run.insecure_tls", value)
	})
	insecureTLSCheck.SetChecked(a.Preferences().BoolWithFallback("run.insecure_tls", false))
	authorizedCheck := widget.NewCheck("我确认目标已获授权", nil)

	statusLabel := widget.NewLabel("就绪")
	selectedLabel := widget.NewLabel("当前未选择节点")
	progressBar := widget.NewProgressBar()
	progressBar.SetValue(0)

	totalValue := widget.NewLabel("0")
	doneValue := widget.NewLabel("0")
	vulnValue := widget.NewLabel("0")
	errValue := widget.NewLabel("0")
	cancelValue := widget.NewLabel("0")
	for _, label := range []*widget.Label{totalValue, doneValue, vulnValue, errValue, cancelValue} {
		label.Alignment = fyne.TextAlignCenter
		label.TextStyle = fyne.TextStyle{Bold: true}
		label.SizeName = theme.SizeNameHeadingText
	}
	totalValue.Importance = widget.HighImportance
	doneValue.Importance = widget.HighImportance
	vulnValue.Importance = widget.SuccessImportance
	errValue.Importance = widget.DangerImportance
	cancelValue.Importance = widget.WarningImportance

	richLog := widget.NewRichText()
	logScroll := container.NewVScroll(richLog)
	logScroll.SetMinSize(fyne.NewSize(0, 240))

	const maxLogEntries = 400
	logEntries := make([]logEntry, 0, maxLogEntries)

	refreshLog := func() {
		segments := make([]widget.RichTextSegment, 0, len(logEntries)*2)
		for _, entry := range logEntries {
			colorName := theme.ColorNameForeground
			switch entry.Level {
			case "VULN":
				colorName = theme.ColorNameSuccess
			case "ERR":
				colorName = theme.ColorNameError
			case "CANCEL":
				colorName = theme.ColorNameDisabled
			case "INFO":
				colorName = theme.ColorNamePrimary
			}

			segments = append(segments,
				&widget.TextSegment{
					Text: entry.At.Format("15:04:05") + " ",
					Style: widget.RichTextStyle{
						ColorName: theme.ColorNameDisabled,
						TextStyle: fyne.TextStyle{Monospace: true},
					},
				},
				&widget.TextSegment{
					Text: "[" + entry.Level + "] " + entry.Message + "\n",
					Style: widget.RichTextStyle{
						ColorName: colorName,
						TextStyle: fyne.TextStyle{Monospace: true},
					},
				},
			)
		}

		richLog.Segments = segments
		richLog.Refresh()
		logScroll.ScrollToBottom()
	}

	appendLogUI := func(level, message string) {
		logEntries = append(logEntries, logEntry{Level: level, Message: message, At: time.Now()})
		if len(logEntries) > maxLogEntries {
			logEntries = append([]logEntry(nil), logEntries[len(logEntries)-maxLogEntries:]...)
		}
		refreshLog()
	}

	updateSummaryUI := func(summary runSummary) {
		totalValue.SetText(strconv.Itoa(summary.Total))
		doneValue.SetText(strconv.Itoa(summary.Done))
		vulnValue.SetText(strconv.Itoa(summary.Vuln))
		errValue.SetText(strconv.Itoa(summary.Err))
		cancelValue.SetText(strconv.Itoa(summary.Cancel))

		if summary.Total == 0 {
			progressBar.SetValue(0)
			return
		}
		progressBar.SetValue(float64(summary.Done) / float64(summary.Total))
	}

	currentSummary := runSummary{}
	isRunning := false
	var runCancel context.CancelFunc
	sessionResults := make([]ExploitResult, 0, 64)
	var currentSelectedID string

	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("节点名称")

	methodSelect := widget.NewSelect([]string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}, nil)
	pathEntry := widget.NewEntry()
	pathEntry.SetPlaceHolder("/api/v1/login")

	paramsEntry := widget.NewEntry()
	paramsEntry.SetPlaceHolder("id=1&debug=true")

	bodyTypeSelect := widget.NewSelect([]string{"Raw", "JSON", "Form"}, nil)
	bodyTypeSelect.SetSelected("Raw")

	bodyEntry := widget.NewMultiLineEntry()
	bodyEntry.SetPlaceHolder("请求 Body")
	bodyEntry.Wrapping = fyne.TextWrapWord
	bodyScroll := container.NewScroll(bodyEntry)
	bodyScroll.SetMinSize(fyne.NewSize(0, 120))

	headersEntry := widget.NewMultiLineEntry()
	headersEntry.SetPlaceHolder("Cookie: session=abc123\nX-Token: demo")
	headersEntry.Wrapping = fyne.TextWrapWord
	headersScroll := container.NewScroll(headersEntry)
	headersScroll.SetMinSize(fyne.NewSize(0, 100))

	matchEntry := widget.NewEntry()
	matchEntry.SetPlaceHolder("示例：duration:>=5s && status:200，或 timeout:true")
	matchHelpLabel := widget.NewLabel("支持状态码、响应头、响应体、正则、响应耗时和预期超时。延时注入示例：duration:>=5s；若预期请求达到客户端超时：timeout:true && duration:>=5s。AND 优先于 OR。")
	matchHelpLabel.Wrapping = fyne.TextWrapWord
	matchHelpLabel.Importance = widget.LowImportance

	saveBtn := widget.NewButtonWithIcon("保存节点", theme.DocumentSaveIcon(), nil)
	pasteRequestBtn := widget.NewButtonWithIcon("粘贴 HTTP 请求", theme.ContentPasteIcon(), nil)
	pasteRequestBtn.Disable()
	clearLogBtn := widget.NewButtonWithIcon("清空日志", theme.DeleteIcon(), func() {
		logEntries = logEntries[:0]
		refreshLog()
		statusLabel.SetText("日志已清空")
	})
	clearResultsBtn := widget.NewButtonWithIcon("清空结果", theme.ContentClearIcon(), nil)
	importTargetsBtn := widget.NewButtonWithIcon("导入目标", theme.UploadIcon(), nil)
	clearTargetsBtn := widget.NewButtonWithIcon("清空", theme.ContentClearIcon(), func() {
		targetEntry.SetText("")
	})
	viewEvidenceBtn := widget.NewButtonWithIcon("查看 / 截图凭证", theme.VisibilityIcon(), nil)
	exportHTMLBtn := widget.NewButtonWithIcon("导出 HTML", theme.DownloadIcon(), nil)
	exportCSVBtn := widget.NewButtonWithIcon("导出 CSV", theme.DownloadIcon(), nil)
	exportJSONBtn := widget.NewButtonWithIcon("导出 JSON", theme.DocumentSaveIcon(), nil)
	singleTestBtn := widget.NewButtonWithIcon("仅验证当前 POC", theme.MediaPlayIcon(), nil)
	batchTestBtn := widget.NewButtonWithIcon("运行所选节点全部 POC", theme.MediaSkipNextIcon(), nil)
	batchTestBtn.Importance = widget.HighImportance
	scopeLabel := widget.NewLabelWithStyle("尚未选择验证范围", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	scopeDetailLabel := widget.NewLabel("在左侧选择产品文件夹，可一次运行其下全部 POC")
	scopeDetailLabel.Importance = widget.LowImportance
	stopTestBtn := widget.NewButtonWithIcon("停止", theme.MediaStopIcon(), nil)
	stopTestBtn.Disable()
	clearResultsBtn.Disable()
	viewEvidenceBtn.Disable()
	exportHTMLBtn.Disable()
	exportCSVBtn.Disable()
	exportJSONBtn.Disable()

	importTargetsBtn.OnTapped = func() {
		openDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if reader == nil {
				return
			}
			defer reader.Close()
			payload, err := io.ReadAll(io.LimitReader(reader, 1024*1024+1))
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if len(payload) > 1024*1024 {
				dialog.ShowError(fmt.Errorf("目标文件不能超过 1 MiB"), w)
				return
			}
			if _, err := parseTargets(string(payload)); err != nil {
				dialog.ShowError(err, w)
				return
			}
			targetEntry.SetText(string(payload))
			statusLabel.SetText("目标列表导入成功")
		}, w)
		openDialog.SetFilter(storage.NewExtensionFileFilter([]string{".txt", ".list"}))
		openDialog.Show()
	}

	pasteRequestBtn.OnTapped = func() {
		if isRunning {
			appendLogUI("INFO", "当前正在执行验证，请等待完成后再导入请求包")
			return
		}
		if currentSelectedID == "" {
			dialog.ShowInformation("提示", "请先选择一个 POC 节点", w)
			return
		}
		node, ok := data.Nodes[currentSelectedID]
		if !ok || node.IsGroup {
			dialog.ShowInformation("提示", "HTTP 请求包只能导入到 POC 节点", w)
			return
		}

		rawEntry := widget.NewMultiLineEntry()
		rawEntry.Wrapping = fyne.TextWrapOff
		rawEntry.SetPlaceHolder("POST /api/login?debug=true HTTP/1.1\nHost: example.com\nContent-Type: application/json\nAuthorization: Bearer token\n\n{\"username\":\"admin\"}")
		rawScroll := container.NewScroll(rawEntry)
		rawScroll.SetMinSize(fyne.NewSize(820, 430))
		errorLabel := widget.NewLabel("")
		errorLabel.Importance = widget.DangerImportance
		helpLabel := widget.NewLabel("粘贴 HTTP/1.x 原始请求。将导入方法、路径、参数、Headers、Body 和 Body 类型；POC 名称与匹配规则保持不变。Host、Content-Length、Connection 等传输层 Header 不会固化，以便同一 POC 可用于多个目标。")
		helpLabel.Wrapping = fyne.TextWrapWord
		content := container.NewBorder(
			container.NewVBox(helpLabel, errorLabel, widget.NewSeparator()),
			nil,
			nil,
			nil,
			rawScroll,
		)
		importDialog := dialog.NewCustomWithoutButtons("导入原始 HTTP 请求", content, w)
		cancelBtn := widget.NewButtonWithIcon("取消", theme.CancelIcon(), importDialog.Hide)
		applyBtn := widget.NewButtonWithIcon("解析并应用", theme.ConfirmIcon(), func() {
			parsed, err := parseRawHTTPRequest(rawEntry.Text)
			if err != nil {
				errorLabel.SetText(err.Error())
				return
			}

			methodSelect.SetSelected(parsed.Method)
			pathEntry.SetText(parsed.Path)
			paramsEntry.SetText(parsed.Params)
			bodyTypeSelect.SetSelected(parsed.BodyType)
			bodyEntry.SetText(parsed.Body)
			headersEntry.SetText(parsed.Headers)
			importDialog.Hide()

			message := fmt.Sprintf("HTTP 请求已导入：%s %s", parsed.Method, parsed.Path)
			if parsed.Host != "" {
				message += fmt.Sprintf("（原始 Host: %s，未固定到 POC）", parsed.Host)
			}
			appendLogUI("INFO", message)
			statusLabel.SetText("HTTP 请求已解析并应用，请确认后保存")
		})
		applyBtn.Importance = widget.HighImportance
		importDialog.SetButtons([]fyne.CanvasObject{cancelBtn, applyBtn})
		importDialog.SetIcon(theme.ContentPasteIcon())
		importDialog.Show()
		w.Canvas().Focus(rawEntry)
	}

	resultSearchEntry := widget.NewEntry()
	resultSearchEntry.SetPlaceHolder("搜索目标、POC、URL 或验证说明")
	resultStatusSelect := widget.NewSelect([]string{"全部结果", "确认命中", "未命中", "执行错误", "已取消"}, nil)
	resultStatusSelect.SetSelected("全部结果")
	filteredResultIndices := make([]int, 0, 64)
	selectedResultIndex := -1
	resultViewCountLabel := widget.NewLabel("显示 0 / 0")
	resultViewCountLabel.Importance = widget.LowImportance
	emptyResultLabel := widget.NewLabelWithStyle("暂无验证结果\n运行验证后，结果会以卡片形式显示在这里", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	emptyResultLabel.Importance = widget.LowImportance

	matchesResultView := func(result ExploitResult) bool {
		switch resultStatusSelect.Selected {
		case "确认命中":
			if result.Level != "VULN" {
				return false
			}
		case "未命中":
			if result.Level != "SAFE" {
				return false
			}
		case "执行错误":
			if result.Level != "ERR" {
				return false
			}
		case "已取消":
			if result.Level != "CANCEL" {
				return false
			}
		}
		keyword := strings.ToLower(strings.TrimSpace(resultSearchEntry.Text))
		if keyword == "" {
			return true
		}
		haystack := strings.ToLower(strings.Join([]string{result.Target, result.POCName, result.URL, result.Message, result.Level}, "\n"))
		return strings.Contains(haystack, keyword)
	}

	resultList := widget.NewList(
		func() int { return len(filteredResultIndices) },
		func() fyne.CanvasObject { return newResultListRow() },
		func(id widget.ListItemID, object fyne.CanvasObject) {
			if id < 0 || id >= len(filteredResultIndices) {
				return
			}
			resultIndex := filteredResultIndices[id]
			if resultIndex < 0 || resultIndex >= len(sessionResults) {
				return
			}
			object.(*resultListRow).SetResult(sessionResults[resultIndex])
		},
	)
	resultList.HideSeparators = true

	rebuildResultView := func() {
		filteredResultIndices = filteredResultIndices[:0]
		for index, result := range sessionResults {
			if matchesResultView(result) {
				filteredResultIndices = append(filteredResultIndices, index)
			}
		}
		selectedResultIndex = -1
		viewEvidenceBtn.Disable()
		resultViewCountLabel.SetText(fmt.Sprintf("显示 %d / %d", len(filteredResultIndices), len(sessionResults)))
		if len(filteredResultIndices) == 0 {
			emptyResultLabel.Show()
		} else {
			emptyResultLabel.Hide()
		}
		resultList.UnselectAll()
		resultList.Refresh()
	}
	resultSearchEntry.OnChanged = func(string) { rebuildResultView() }
	resultStatusSelect.OnChanged = func(string) { rebuildResultView() }

	resultList.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(filteredResultIndices) {
			selectedResultIndex = -1
			viewEvidenceBtn.Disable()
			return
		}
		selectedResultIndex = filteredResultIndices[id]
		viewEvidenceBtn.Enable()
	}
	resultList.OnUnselected = func(id widget.ListItemID) {
		if id >= 0 && id < len(filteredResultIndices) && filteredResultIndices[id] == selectedResultIndex {
			selectedResultIndex = -1
			viewEvidenceBtn.Disable()
		}
	}
	viewEvidenceBtn.OnTapped = func() {
		if selectedResultIndex < 0 || selectedResultIndex >= len(sessionResults) {
			viewEvidenceBtn.Disable()
			return
		}
		showResultEvidenceDialog(w, sessionResults[selectedResultIndex])
	}

	var workspaceTabs *container.AppTabs
	var resultTabs *container.AppTabs
	filterEntry := widget.NewEntry()
	filterEntry.SetPlaceHolder("筛选 POC / 文件夹")

	setPOCFieldsEnabled := func(enabled bool) {
		if enabled {
			methodSelect.Enable()
			pathEntry.Enable()
			paramsEntry.Enable()
			bodyTypeSelect.Enable()
			bodyEntry.Enable()
			headersEntry.Enable()
			matchEntry.Enable()
			return
		}

		methodSelect.Disable()
		pathEntry.Disable()
		paramsEntry.Disable()
		bodyTypeSelect.Disable()
		bodyEntry.Disable()
		headersEntry.Disable()
		matchEntry.Disable()
	}

	clearEditor := func() {
		nameEntry.SetText("")
		methodSelect.ClearSelected()
		pathEntry.SetText("")
		paramsEntry.SetText("")
		bodyTypeSelect.SetSelected("Raw")
		bodyEntry.SetText("")
		headersEntry.SetText("")
		matchEntry.SetText("")
	}

	setSelectedValue := func(selectWidget *widget.Select, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			selectWidget.ClearSelected()
			return
		}
		selectWidget.SetSelected(value)
	}

	refreshScopeSelection := func(nodeID string) {
		if isRunning {
			singleTestBtn.Disable()
			batchTestBtn.Disable()
			return
		}
		node, ok := data.Nodes[nodeID]
		if !ok {
			scopeLabel.SetText("尚未选择验证范围")
			scopeDetailLabel.SetText("在左侧选择产品文件夹，可一次运行其下全部 POC")
			singleTestBtn.Disable()
			batchTestBtn.Disable()
			batchTestBtn.SetText("运行所选节点全部 POC")
			return
		}
		pocCount := len(data.collectPOCs(nodeID))
		if node.IsGroup {
			scopeLabel.SetText("验证范围：" + node.Name)
			scopeDetailLabel.SetText(fmt.Sprintf("将对每个目标运行该节点下全部 %d 个 POC", pocCount))
			singleTestBtn.Disable()
			batchTestBtn.SetText(fmt.Sprintf("运行「%s」全部 POC（%d）", node.Name, pocCount))
			if pocCount > 0 {
				batchTestBtn.Enable()
			} else {
				batchTestBtn.Disable()
			}
			return
		}
		scopeLabel.SetText("当前 POC：" + node.Name)
		scopeDetailLabel.SetText("仅运行当前 POC；也可选择其上级产品节点批量运行")
		if node.Data != nil {
			singleTestBtn.Enable()
			batchTestBtn.Enable()
			batchTestBtn.SetText("运行当前 POC")
		} else {
			singleTestBtn.Disable()
			batchTestBtn.Disable()
		}
	}

	loadNodeToEditor := func(nodeID string) {
		refreshScopeSelection(nodeID)
		currentSelectedID = nodeID
		if nodeID == "" {
			selectedLabel.SetText("当前未选择节点")
			nameEntry.Disable()
			setPOCFieldsEnabled(false)
			saveBtn.Disable()
			pasteRequestBtn.Disable()
			clearEditor()
			return
		}

		node, ok := data.Nodes[nodeID]
		if !ok {
			selectedLabel.SetText("当前节点不存在")
			nameEntry.Disable()
			setPOCFieldsEnabled(false)
			saveBtn.Disable()
			pasteRequestBtn.Disable()
			clearEditor()
			return
		}

		selectedLabel.SetText(fmt.Sprintf("当前节点：%s", node.Name))
		nameEntry.Enable()
		saveBtn.Enable()
		pasteRequestBtn.Disable()
		nameEntry.SetText(node.Name)

		if node.IsGroup {
			methodSelect.ClearSelected()
			pathEntry.SetText("")
			paramsEntry.SetText("")
			bodyTypeSelect.SetSelected("Raw")
			bodyEntry.SetText("")
			headersEntry.SetText("")
			matchEntry.SetText("")
			setPOCFieldsEnabled(false)
			return
		}

		if node.Data == nil {
			node.Data = &POC{Name: node.Name, Method: "GET", Path: "/", BodyType: "Raw"}
		}

		pasteRequestBtn.Enable()
		setSelectedValue(methodSelect, node.Data.Method)
		pathEntry.SetText(node.Data.Path)
		paramsEntry.SetText(node.Data.Params)
		bodyTypeSelect.SetSelected(strings.TrimSpace(defaultString(node.Data.BodyType, "Raw")))
		bodyEntry.SetText(node.Data.Body)
		headersEntry.SetText(node.Data.Headers)
		matchEntry.SetText(node.Data.MatchRule)
		setPOCFieldsEnabled(true)
	}

	persistData := func(successMessage string) bool {
		if err := saveDataToFile(dataFilePath, data); err != nil {
			dialog.ShowError(err, w)
			appendLogUI("ERR", fmt.Sprintf("保存失败: %v", err))
			statusLabel.SetText("保存失败")
			return false
		}

		if successMessage != "" {
			appendLogUI("INFO", successMessage)
			statusLabel.SetText(successMessage)
		}
		return true
	}

	parseRunSettings := func() (RunSettings, int, error) {
		if !authorizedCheck.Checked {
			return RunSettings{}, 0, fmt.Errorf("请先确认目标已获得安全测试授权")
		}

		timeoutSeconds, err := strconv.Atoi(strings.TrimSpace(timeoutEntry.Text))
		if err != nil || timeoutSeconds <= 0 {
			return RunSettings{}, 0, fmt.Errorf("超时时间必须是正整数")
		}

		concurrency, err := strconv.Atoi(strings.TrimSpace(concurrencySelect.Selected))
		if err != nil || concurrency <= 0 {
			return RunSettings{}, 0, fmt.Errorf("并发数无效")
		}

		return RunSettings{
			Timeout:            time.Duration(timeoutSeconds) * time.Second,
			InsecureSkipVerify: insecureTLSCheck.Checked,
		}, concurrency, nil
	}

	setRunningStateUI := func(running bool, status string) {
		isRunning = running
		if running {
			singleTestBtn.Disable()
			batchTestBtn.Disable()
			stopTestBtn.Enable()
			clearResultsBtn.Disable()
		} else {
			stopTestBtn.Disable()
			refreshScopeSelection(currentSelectedID)
			if len(sessionResults) > 0 {
				clearResultsBtn.Enable()
			}
		}
		statusLabel.SetText(status)
	}

	startRunUI := func(total int, status string) context.Context {
		if runCancel != nil {
			runCancel()
		}
		runContext, cancel := context.WithCancel(context.Background())
		runCancel = cancel
		currentSummary = runSummary{Total: total}
		updateSummaryUI(currentSummary)
		setRunningStateUI(true, status)
		return runContext
	}

	finishRunUI := func(status string) {
		runCancel = nil
		setRunningStateUI(false, status)
	}

	applyResultUI := func(result ExploitResult) {
		currentSummary.Done++
		switch result.Level {
		case "VULN":
			currentSummary.Vuln++
		case "ERR":
			currentSummary.Err++
		case "CANCEL":
			currentSummary.Cancel++
		}
		sessionResults = append(sessionResults, result)
		rebuildResultView()
		if !isRunning {
			clearResultsBtn.Enable()
		}
		exportHTMLBtn.Enable()
		exportCSVBtn.Enable()
		exportJSONBtn.Enable()
		updateSummaryUI(currentSummary)
		logMessage := result.Message
		if strings.TrimSpace(result.Target) != "" {
			logMessage = fmt.Sprintf("%s · %s", result.Target, result.Message)
		}
		appendLogUI(result.Level, logMessage)
	}

	stopTestBtn.OnTapped = func() {
		if runCancel == nil {
			return
		}
		statusLabel.SetText("正在停止验证…")
		appendLogUI("INFO", "用户请求停止当前验证任务")
		stopTestBtn.Disable()
		runCancel()
	}

	clearResultsBtn.OnTapped = func() {
		if isRunning {
			return
		}
		sessionResults = sessionResults[:0]
		rebuildResultView()
		currentSummary = runSummary{}
		updateSummaryUI(currentSummary)
		selectedResultIndex = -1
		viewEvidenceBtn.Disable()
		clearResultsBtn.Disable()
		exportHTMLBtn.Disable()
		exportCSVBtn.Disable()
		exportJSONBtn.Disable()
		appendLogUI("INFO", "会话验证结果已清空")
	}

	exportResultFile := func(fileName string, exporter func(fyne.URIWriteCloser, []ExploitResult) error) {
		if len(sessionResults) == 0 {
			dialog.ShowInformation("提示", "当前没有可导出的验证结果", w)
			return
		}
		resultsCopy := append([]ExploitResult(nil), sessionResults...)
		saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if writer == nil {
				return
			}
			defer writer.Close()
			if err := exporter(writer, resultsCopy); err != nil {
				dialog.ShowError(err, w)
				return
			}
			appendLogUI("INFO", fmt.Sprintf("验证报告导出成功：%s", writer.URI().Name()))
		}, w)
		saveDialog.SetFileName(fileName)
		saveDialog.Show()
	}

	exportHTMLBtn.OnTapped = func() {
		exportResultFile("ALL1n-results.html", func(writer fyne.URIWriteCloser, results []ExploitResult) error {
			return exportResultsHTML(writer, results)
		})
	}
	exportCSVBtn.OnTapped = func() {
		exportResultFile("ALL1n-results.csv", func(writer fyne.URIWriteCloser, results []ExploitResult) error {
			return exportResultsCSV(writer, results)
		})
	}
	exportJSONBtn.OnTapped = func() {
		exportResultFile("ALL1n-results.json", func(writer fyne.URIWriteCloser, results []ExploitResult) error {
			return exportResultsJSON(writer, results)
		})
	}

	var matchesFilter func(string, string) bool
	matchesFilter = func(nodeID, keyword string) bool {
		node, ok := data.Nodes[nodeID]
		if !ok {
			return false
		}

		if keyword == "" {
			return true
		}

		nameMatched := strings.Contains(strings.ToLower(node.Name), keyword)
		if nameMatched {
			return true
		}

		if node.IsGroup {
			for _, childID := range node.Children {
				if matchesFilter(childID, keyword) {
					return true
				}
			}
		}
		return false
	}

	var tree *widget.Tree
	tree = widget.NewTree(
		func(id widget.TreeNodeID) []widget.TreeNodeID {
			keyword := strings.ToLower(strings.TrimSpace(filterEntry.Text))
			if id == "" {
				visibleRoots := make([]string, 0, len(data.RootIDs))
				for _, rootID := range data.RootIDs {
					if matchesFilter(rootID, keyword) {
						visibleRoots = append(visibleRoots, rootID)
					}
				}
				return visibleRoots
			}

			node, ok := data.Nodes[id]
			if !ok {
				return nil
			}

			if keyword == "" {
				return append([]string(nil), node.Children...)
			}

			visibleChildren := make([]string, 0, len(node.Children))
			for _, childID := range node.Children {
				if matchesFilter(childID, keyword) {
					visibleChildren = append(visibleChildren, childID)
				}
			}
			return visibleChildren
		},
		func(id widget.TreeNodeID) bool {
			if id == "" {
				return true
			}
			node, ok := data.Nodes[id]
			return ok && node.IsGroup
		},
		func(branch bool) fyne.CanvasObject {
			icon := theme.FileIcon()
			if branch {
				icon = theme.FolderIcon()
			}
			return container.NewHBox(widget.NewIcon(icon), widget.NewLabel("节点"))
		},
		func(id widget.TreeNodeID, branch bool, object fyne.CanvasObject) {
			node, ok := data.Nodes[id]
			if !ok {
				return
			}

			objects := object.(*fyne.Container).Objects
			objects[0].(*widget.Icon).SetResource(theme.FileIcon())
			if branch {
				objects[0].(*widget.Icon).SetResource(theme.FolderIcon())
			}
			objects[1].(*widget.Label).SetText(node.Name)
		},
	)
	tree.OnSelected = func(id widget.TreeNodeID) {
		loadNodeToEditor(id)
	}

	filterEntry.OnChanged = func(_ string) {
		tree.Refresh()
	}

	addFolderBtn := widget.NewButtonWithIcon("新建文件夹", theme.FolderNewIcon(), func() {
		if isRunning {
			appendLogUI("INFO", "当前正在执行验证，请等待完成后再修改树结构")
			return
		}

		parentID := ""
		if currentSelectedID != "" {
			node, ok := data.Nodes[currentSelectedID]
			if !ok {
				dialog.ShowError(fmt.Errorf("当前节点不存在"), w)
				return
			}
			if !node.IsGroup {
				dialog.ShowInformation("提示", "请先选中文件夹再创建子文件夹", w)
				return
			}
			parentID = currentSelectedID
		}

		node, err := data.addGroup(parentID, "新建文件夹")
		if err != nil {
			dialog.ShowError(err, w)
			return
		}

		tree.Refresh()
		tree.Select(node.ID)
		_ = persistData("已创建文件夹")
	})

	addPOCBtn := widget.NewButtonWithIcon("新建 POC", theme.FileIcon(), func() {
		if isRunning {
			appendLogUI("INFO", "当前正在执行验证，请等待完成后再修改树结构")
			return
		}

		if currentSelectedID == "" {
			dialog.ShowInformation("提示", "请先选择一个文件夹", w)
			return
		}

		node, ok := data.Nodes[currentSelectedID]
		if !ok {
			dialog.ShowError(fmt.Errorf("当前节点不存在"), w)
			return
		}
		if !node.IsGroup {
			dialog.ShowInformation("提示", "请选择文件夹后再创建 POC", w)
			return
		}

		newNode, err := data.addPOC(currentSelectedID, &POC{
			Name:     "新建POC",
			Method:   "GET",
			Path:     "/",
			BodyType: "Raw",
		})
		if err != nil {
			dialog.ShowError(err, w)
			return
		}

		tree.Refresh()
		tree.Select(newNode.ID)
		_ = persistData("已创建 POC")
	})

	deleteBtn := widget.NewButtonWithIcon("删除", theme.DeleteIcon(), func() {
		if isRunning {
			appendLogUI("INFO", "当前正在执行验证，请等待完成后再删除节点")
			return
		}

		if currentSelectedID == "" {
			dialog.ShowInformation("提示", "请先选择一个节点", w)
			return
		}

		node, ok := data.Nodes[currentSelectedID]
		if !ok {
			dialog.ShowError(fmt.Errorf("当前节点不存在"), w)
			return
		}

		dialog.NewConfirm(
			"确认删除",
			fmt.Sprintf("确定删除“%s”及其所有子节点吗？", node.Name),
			func(ok bool) {
				if !ok {
					return
				}

				if err := data.deleteNode(currentSelectedID); err != nil {
					dialog.ShowError(err, w)
					return
				}

				tree.UnselectAll()
				tree.Refresh()
				loadNodeToEditor("")
				_ = persistData("节点已删除")
			},
			w,
		).Show()
	})

	exportBtn := widget.NewButtonWithIcon("导出", theme.DownloadIcon(), func() {
		saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if writer == nil {
				return
			}
			defer writer.Close()

			if err := exportData(writer, data); err != nil {
				dialog.ShowError(err, w)
				return
			}

			appendLogUI("INFO", "数据导出成功")
			statusLabel.SetText("数据导出成功")
		}, w)
		saveDialog.SetFileName("poc_data_backup.json")
		saveDialog.Show()
	})

	importBtn := widget.NewButtonWithIcon("导入", theme.UploadIcon(), func() {
		if isRunning {
			appendLogUI("INFO", "当前正在执行验证，请等待完成后再导入数据")
			return
		}

		openDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if reader == nil {
				return
			}
			defer reader.Close()

			importedData, err := importData(reader)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}

			dialog.NewConfirm(
				"导入确认",
				"导入会覆盖当前内存中的所有节点，是否继续？",
				func(ok bool) {
					if !ok {
						return
					}

					data = importedData
					filterEntry.SetText("")
					tree.UnselectAll()
					tree.Refresh()
					loadNodeToEditor("")
					if persistData("数据已导入并保存") {
						statusLabel.SetText("数据已导入并保存")
					}
				},
				w,
			).Show()
		}, w)
		openDialog.SetFilter(storage.NewExtensionFileFilter([]string{".json"}))
		openDialog.Show()
	})

	saveBtn.OnTapped = func() {
		if currentSelectedID == "" {
			dialog.ShowInformation("提示", "请先选择一个节点", w)
			return
		}

		node, ok := data.Nodes[currentSelectedID]
		if !ok {
			dialog.ShowError(fmt.Errorf("当前节点不存在"), w)
			return
		}

		nodeName := strings.TrimSpace(nameEntry.Text)
		if nodeName == "" {
			dialog.ShowInformation("提示", "节点名称不能为空", w)
			return
		}

		node.Name = nodeName
		if node.IsGroup {
			tree.Refresh()
			_ = persistData("文件夹已保存")
			return
		}

		if node.Data == nil {
			node.Data = &POC{}
		}

		node.Data.Name = nodeName
		node.Data.Method = defaultString(methodSelect.Selected, "GET")
		node.Data.Path = strings.TrimSpace(pathEntry.Text)
		node.Data.Params = strings.TrimSpace(paramsEntry.Text)
		node.Data.BodyType = defaultString(bodyTypeSelect.Selected, "Raw")
		node.Data.Body = bodyEntry.Text
		node.Data.Headers = headersEntry.Text
		node.Data.MatchRule = matchEntry.Text

		tree.Refresh()
		_ = persistData("POC 已保存")
	}

	executeTasksUI := func(tasks []RunTask, settings RunSettings, concurrency int, title string) {
		if len(tasks) == 0 {
			appendLogUI("INFO", "没有可执行的验证任务")
			return
		}

		appendLogUI("INFO", fmt.Sprintf("=== %s：共 %d 个任务，%d 并发 ===", title, len(tasks), concurrency))
		if workspaceTabs != nil {
			workspaceTabs.SelectIndex(1)
		}
		if resultTabs != nil {
			resultTabs.SelectIndex(1)
		}
		runContext := startRunUI(len(tasks), fmt.Sprintf("正在执行 %d 个验证任务", len(tasks)))
		go func() {
			for result := range RunBatch(runContext, runner, tasks, settings, concurrency) {
				resultCopy := result
				fyne.Do(func() {
					applyResultUI(resultCopy)
					statusLabel.SetText(fmt.Sprintf("验证进行中 %d/%d", currentSummary.Done, currentSummary.Total))
				})
			}

			fyne.Do(func() {
				if runContext.Err() != nil {
					remaining := currentSummary.Total - currentSummary.Done
					if remaining > 0 {
						currentSummary.Done += remaining
						currentSummary.Cancel += remaining
						updateSummaryUI(currentSummary)
					}
					appendLogUI("INFO", fmt.Sprintf("=== 验证已停止：命中 %d，错误 %d，取消 %d ===", currentSummary.Vuln, currentSummary.Err, currentSummary.Cancel))
					finishRunUI("验证已停止")
					return
				}
				appendLogUI("INFO", fmt.Sprintf("=== 验证完成：命中 %d，错误 %d ===", currentSummary.Vuln, currentSummary.Err))
				finishRunUI("验证完成")
			})
		}()
	}

	parseRunInput := func() ([]string, RunSettings, int, error) {
		targets, err := parseTargets(targetEntry.Text)
		if err != nil {
			return nil, RunSettings{}, 0, err
		}
		settings, concurrency, err := parseRunSettings()
		if err != nil {
			return nil, RunSettings{}, 0, err
		}
		return targets, settings, concurrency, nil
	}

	singleTestBtn.OnTapped = func() {
		if isRunning {
			return
		}
		if currentSelectedID == "" {
			appendLogUI("ERR", "请先选择一个 POC 节点")
			return
		}

		node, ok := data.Nodes[currentSelectedID]
		if !ok || node.IsGroup || node.Data == nil {
			appendLogUI("ERR", "请选择一个有效的 POC 节点")
			return
		}
		targets, settings, concurrency, err := parseRunInput()
		if err != nil {
			appendLogUI("ERR", err.Error())
			return
		}

		poc := clonePOC(node.Data)
		tasks := buildRunTasks(targets, []*POC{poc})
		executeTasksUI(tasks, settings, concurrency, fmt.Sprintf("验证当前 POC「%s」：%d 个目标", poc.Name, len(targets)))
	}

	batchTestBtn.OnTapped = func() {
		if isRunning {
			return
		}
		if currentSelectedID == "" {
			appendLogUI("ERR", "请先选择要验证的 POC 或文件夹范围")
			return
		}

		pocs := data.collectPOCs(currentSelectedID)
		if len(pocs) == 0 {
			appendLogUI("INFO", "当前范围内没有可执行的 POC")
			return
		}
		targets, settings, concurrency, err := parseRunInput()
		if err != nil {
			appendLogUI("ERR", err.Error())
			return
		}

		scopeName := currentSelectedID
		if node, ok := data.Nodes[currentSelectedID]; ok {
			scopeName = node.Name
		}
		tasks := buildRunTasks(targets, pocs)
		executeTasksUI(tasks, settings, concurrency, fmt.Sprintf("验证范围「%s」：%d 个目标 × %d 个 POC", scopeName, len(targets), len(pocs)))
	}

	toolBar := container.NewGridWithColumns(3, addFolderBtn, addPOCBtn, deleteBtn)
	dataBar := container.NewGridWithColumns(2, exportBtn, importBtn)

	leftPanel := newSurfacePanel(
		"POC 库",
		"按名称筛选并组织验证模板",
		container.NewBorder(
			container.NewVBox(filterEntry, toolBar, widget.NewSeparator()),
			container.NewVBox(widget.NewSeparator(), dataBar),
			nil,
			nil,
			container.NewPadded(tree),
		),
	)

	form := widget.NewForm(
		widget.NewFormItem("名称", nameEntry),
		widget.NewFormItem("请求方法", methodSelect),
		widget.NewFormItem("路径", pathEntry),
		widget.NewFormItem("查询参数", paramsEntry),
		widget.NewFormItem("Body 类型", bodyTypeSelect),
		widget.NewFormItem("Body", bodyScroll),
		widget.NewFormItem("Headers", headersScroll),
		widget.NewFormItem("匹配规则", matchEntry),
	)

	editorContent := container.NewVBox(
		selectedLabel,
		widget.NewSeparator(),
		form,
		matchHelpLabel,
		container.NewHBox(layout.NewSpacer(), pasteRequestBtn, saveBtn),
	)
	editorScroll := container.NewVScroll(container.NewPadded(editorContent))
	editorPanel := newSurfacePanel(
		"请求定义",
		"配置当前 POC 的请求与命中条件",
		editorScroll,
	)

	summaryGrid := container.NewGridWithColumns(
		5,
		widget.NewCard("任务总数", "TARGET × POC", totalValue),
		widget.NewCard("已完成", "实时执行进度", doneValue),
		widget.NewCard("确认命中", "需要重点复核", vulnValue),
		widget.NewCard("执行错误", "网络或规则异常", errValue),
		widget.NewCard("已取消", "未完成的任务", cancelValue),
	)

	resultTabs = container.NewAppTabs(
		container.NewTabItem("运行日志", logScroll),
		container.NewTabItem("结构化结果", container.NewBorder(
			container.NewBorder(nil, nil, resultStatusSelect, resultViewCountLabel, resultSearchEntry),
			nil, nil, nil,
			container.NewStack(resultList, container.NewCenter(emptyResultLabel)),
		)),
	)
	resultTabs.SetTabLocation(container.TabLocationTop)

	resultPanel := newSurfacePanel(
		"验证结果",
		"实时进度、目标级结果与报告导出",
		container.NewBorder(
			container.NewVBox(summaryGrid, progressBar, widget.NewSeparator()),
			container.NewHBox(layout.NewSpacer(), viewEvidenceBtn, exportHTMLBtn, exportCSVBtn, exportJSONBtn, clearResultsBtn, clearLogBtn),
			nil,
			nil,
			resultTabs,
		),
	)

	workspaceTabs = container.NewAppTabs(
		container.NewTabItemWithIcon("请求定义", theme.DocumentCreateIcon(), editorPanel),
		container.NewTabItemWithIcon("验证结果", theme.InfoIcon(), resultPanel),
	)
	workspaceTabs.SetTabLocation(container.TabLocationTop)

	mainSplit := container.NewHSplit(
		container.NewPadded(leftPanel),
		container.NewPadded(workspaceTabs),
	)
	mainSplit.SetOffset(0.25)

	brandAccent := canvas.NewRectangle(theme.PrimaryColor())
	brandAccent.SetMinSize(fyne.NewSize(5, 48))
	brandTitle := canvas.NewText("ALL1n", theme.ForegroundColor())
	brandTitle.TextSize = 28
	brandTitle.TextStyle = fyne.TextStyle{Bold: true}
	brandSubtitle := canvas.NewText("By 基调听云-hongzh0", theme.DisabledColor())
	brandSubtitle.TextSize = 11
	versionLabel := widget.NewLabelWithStyle(appVersion, fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Monospace: true})

	themeSelect := widget.NewSelect(optionLabels(productThemeOptions), nil)
	themeSelect.SetSelected(optionLabelForID(productThemeOptions, selectedThemeID, defaultThemeID))
	fontSelect := widget.NewSelect(optionLabels(productFontOptions), nil)
	fontSelect.SetSelected(optionLabelForID(productFontOptions, selectedFontID, defaultFontID))
	appearanceControls := container.NewGridWrap(
		fyne.NewSize(126, 40),
		themeSelect,
		fontSelect,
	)
	refreshAppearance := func(message string) {
		a.Settings().SetTheme(newProductTheme(selectedThemeID, selectedFontID))
		brandAccent.FillColor = theme.PrimaryColor()
		brandTitle.Color = theme.ForegroundColor()
		brandSubtitle.Color = theme.DisabledColor()
		brandAccent.Refresh()
		brandTitle.Refresh()
		brandSubtitle.Refresh()
		if message != "" {
			statusLabel.SetText(message)
		}
	}
	themeSelect.OnChanged = func(label string) {
		selectedThemeID = optionIDForLabel(productThemeOptions, label, defaultThemeID)
		a.Preferences().SetString("appearance.theme", selectedThemeID)
		refreshAppearance("主题已切换为「" + label + "」")
	}
	fontSelect.OnChanged = func(label string) {
		selectedFontID = optionIDForLabel(productFontOptions, label, defaultFontID)
		a.Preferences().SetString("appearance.font", selectedFontID)
		refreshAppearance("字体已切换为「" + label + "」")
	}

	brandHeader := container.NewHBox(
		brandAccent,
		container.NewVBox(brandTitle, brandSubtitle),
		layout.NewSpacer(),
		widget.NewLabelWithStyle("外观", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		appearanceControls,
		widget.NewCard("", "", container.NewPadded(versionLabel)),
	)

	targetPanel := newSurfacePanel(
		"目标资产",
		"每行一个目标；自动补全协议、去重并校验，最多 1000 个",
		container.NewBorder(
			nil,
			container.NewHBox(targetCountLabel, layout.NewSpacer(), importTargetsBtn, clearTargetsBtn),
			nil,
			nil,
			targetScroll,
		),
	)

	runOptions := container.NewGridWithColumns(
		2,
		widget.NewForm(widget.NewFormItem("请求超时（秒）", timeoutEntry)),
		widget.NewForm(widget.NewFormItem("全局并发任务", concurrencySelect)),
	)
	timingHint := widget.NewLabel("延时规则提示：duration 阈值应小于请求超时；使用 timeout:true 时，达到该超时本身可作为命中证据。")
	timingHint.Wrapping = fyne.TextWrapWord
	timingHint.Importance = widget.LowImportance
	runPanel := newSurfacePanel(
		"运行配置",
		"目标 × POC 形成任务矩阵，并发统一受控",
		container.NewVBox(
			runOptions,
			timingHint,
			container.NewGridWithColumns(2, insecureTLSCheck, authorizedCheck),
			widget.NewSeparator(),
			container.NewVBox(scopeLabel, scopeDetailLabel),
			container.NewGridWithColumns(3, singleTestBtn, batchTestBtn, stopTestBtn),
		),
	)

	topArea := container.NewVBox(
		brandHeader,
		container.NewGridWithColumns(2, targetPanel, runPanel),
	)

	statusBar := container.NewBorder(
		nil,
		nil,
		widget.NewLabelWithStyle("STATUS", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true}),
		nil,
		statusLabel,
	)

	content := container.NewBorder(
		container.NewPadded(topArea),
		container.NewPadded(statusBar),
		nil,
		nil,
		mainSplit,
	)

	loadNodeToEditor("")

	if loadErr != nil {
		appendLogUI("ERR", fmt.Sprintf("加载数据失败，已切换到默认数据：%v", loadErr))
		statusLabel.SetText("历史数据加载失败，已载入默认数据")
	} else {
		appendLogUI("INFO", "应用已就绪")
	}

	w.SetCloseIntercept(func() {
		if runCancel != nil {
			runCancel()
		}
		runner.CloseIdleConnections()
		if err := saveDataToFile(dataFilePath, data); err != nil {
			dialog.ShowError(err, w)
			return
		}
		w.Close()
	})

	w.SetContent(content)
	w.ShowAndRun()
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
