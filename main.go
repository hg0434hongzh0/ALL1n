package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
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
	Total int
	Done  int
	Vuln  int
	Err   int
}

func main() {
	data, loadErr := loadDataFromFile(dataFile)
	if data == nil {
		data = defaultAppData()
	}

	runner := NewRunner()
	a := app.NewWithID("com.all1n.pocworkbench")
	w := a.NewWindow("ALL1n - POC 验证工作台")
	w.Resize(fyne.NewSize(1480, 920))

	targetEntry := widget.NewEntry()
	targetEntry.SetPlaceHolder("目标地址，例如 http://192.168.1.10:8080")

	timeoutEntry := widget.NewEntry()
	timeoutEntry.SetText("10")
	timeoutEntry.SetPlaceHolder("超时(秒)")

	concurrencySelect := widget.NewSelect([]string{"1", "2", "4", "8"}, nil)
	concurrencySelect.SetSelected("4")

	insecureTLSCheck := widget.NewCheck("忽略 TLS 证书错误", nil)
	insecureTLSCheck.SetChecked(true)

	statusLabel := widget.NewLabel("就绪")
	selectedLabel := widget.NewLabel("当前未选择节点")
	progressBar := widget.NewProgressBar()
	progressBar.SetValue(0)

	totalValue := widget.NewLabel("0")
	doneValue := widget.NewLabel("0")
	vulnValue := widget.NewLabel("0")
	errValue := widget.NewLabel("0")
	for _, label := range []*widget.Label{totalValue, doneValue, vulnValue, errValue} {
		label.Alignment = fyne.TextAlignCenter
		label.TextStyle = fyne.TextStyle{Bold: true}
	}

	richLog := widget.NewRichText()
	logScroll := container.NewVScroll(richLog)
	logScroll.SetMinSize(fyne.NewSize(0, 250))

	const maxLogEntries = 500
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
			case "INFO":
				colorName = theme.ColorNamePrimary
			case "SAFE":
				colorName = theme.ColorNameWarning
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
		if summary.Total == 0 {
			progressBar.SetValue(0)
			return
		}
		progressBar.SetValue(float64(summary.Done) / float64(summary.Total))
	}

	currentSummary := runSummary{}
	isRunning := false

	nodeNameEntry := widget.NewEntry()
	nodeNameEntry.SetPlaceHolder("节点名称")

	stepSelect := widget.NewSelect(nil, nil)
	stepNameEntry := widget.NewEntry()
	stepNameEntry.SetPlaceHolder("步骤名称")

	methodSelect := widget.NewSelect([]string{"GET", "POST", "PUT", "DELETE", "PATCH"}, nil)
	pathEntry := widget.NewEntry()
	pathEntry.SetPlaceHolder("/api/v1/login 或 {{BaseURL}}/api/v1/login")
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
	matchEntry.SetPlaceHolder("支持 body:/status:/header:/headers:/regex:/!/&&/||")

	extractEntry := widget.NewMultiLineEntry()
	extractEntry.SetPlaceHolder("token=body_regex:token=([a-z0-9]+)\nsid=header:Set-Cookie")
	extractEntry.Wrapping = fyne.TextWrapWord
	extractScroll := container.NewScroll(extractEntry)
	extractScroll.SetMinSize(fyne.NewSize(0, 80))

	continueCheck := widget.NewCheck("步骤失败或未命中后继续后续步骤", nil)

	saveBtn := widget.NewButtonWithIcon("保存节点", theme.DocumentSaveIcon(), nil)
	clearLogBtn := widget.NewButtonWithIcon("清空日志", theme.DeleteIcon(), func() {
		logEntries = logEntries[:0]
		refreshLog()
		statusLabel.SetText("日志已清空")
	})
	singleTestBtn := widget.NewButtonWithIcon("单点验证", theme.MediaPlayIcon(), nil)
	batchTestBtn := widget.NewButtonWithIcon("批量验证", theme.MediaSkipNextIcon(), nil)

	addStepBtn := widget.NewButtonWithIcon("新增步骤", theme.ContentAddIcon(), nil)
	duplicateStepBtn := widget.NewButtonWithIcon("复制步骤", theme.ContentCopyIcon(), nil)
	removeStepBtn := widget.NewButtonWithIcon("删除步骤", theme.DeleteIcon(), nil)

	var currentSelectedID string
	currentStepIndex := -1
	stepSelectionGuard := false

	filterEntry := widget.NewEntry()
	filterEntry.SetPlaceHolder("筛选 POC / 文件夹")

	setStepFieldsEnabled := func(enabled bool) {
		if enabled {
			stepSelect.Enable()
			stepNameEntry.Enable()
			methodSelect.Enable()
			pathEntry.Enable()
			paramsEntry.Enable()
			bodyTypeSelect.Enable()
			bodyEntry.Enable()
			headersEntry.Enable()
			matchEntry.Enable()
			extractEntry.Enable()
			continueCheck.Enable()
			addStepBtn.Enable()
			duplicateStepBtn.Enable()
			removeStepBtn.Enable()
			return
		}

		stepSelect.Disable()
		stepNameEntry.Disable()
		methodSelect.Disable()
		pathEntry.Disable()
		paramsEntry.Disable()
		bodyTypeSelect.Disable()
		bodyEntry.Disable()
		headersEntry.Disable()
		matchEntry.Disable()
		extractEntry.Disable()
		continueCheck.Disable()
		addStepBtn.Disable()
		duplicateStepBtn.Disable()
		removeStepBtn.Disable()
	}

	clearStepForm := func() {
		stepNameEntry.SetText("")
		methodSelect.ClearSelected()
		pathEntry.SetText("")
		paramsEntry.SetText("")
		bodyTypeSelect.SetSelected("Raw")
		bodyEntry.SetText("")
		headersEntry.SetText("")
		matchEntry.SetText("")
		extractEntry.SetText("")
		continueCheck.SetChecked(false)
	}

	setStepSelectOptions := func(options []string) {
		stepSelectionGuard = true
		stepSelect.Options = append([]string(nil), options...)
		stepSelect.ClearSelected()
		stepSelect.Refresh()
		stepSelectionGuard = false
	}

	stepOptionLabel := func(index int, step RequestStep) string {
		name := strings.TrimSpace(step.Name)
		if name == "" {
			name = fmt.Sprintf("步骤 %d", index+1)
		}
		return fmt.Sprintf("%d. %s", index+1, name)
	}

	selectedPOC := func() *POC {
		if currentSelectedID == "" {
			return nil
		}
		node, ok := data.Nodes[currentSelectedID]
		if !ok || node.IsGroup || node.Data == nil {
			return nil
		}
		node.Data.normalize()
		return node.Data
	}

	syncCurrentStepFromForm := func() bool {
		poc := selectedPOC()
		if poc == nil || currentStepIndex < 0 || currentStepIndex >= len(poc.Steps) {
			return true
		}

		stepName := strings.TrimSpace(stepNameEntry.Text)
		if stepName == "" {
			stepName = fmt.Sprintf("步骤 %d", currentStepIndex+1)
		}

		step := &poc.Steps[currentStepIndex]
		step.Name = stepName
		step.Method = valueOr(methodSelect.Selected, "GET")
		step.Path = strings.TrimSpace(pathEntry.Text)
		step.Params = strings.TrimSpace(paramsEntry.Text)
		step.BodyType = valueOr(bodyTypeSelect.Selected, "Raw")
		step.Body = bodyEntry.Text
		step.Headers = headersEntry.Text
		step.MatchRule = matchEntry.Text
		step.ExtractRules = extractEntry.Text
		step.ContinueOnError = continueCheck.Checked
		step.normalize(currentStepIndex)

		poc.normalize()
		return true
	}

	loadStepToForm := func(index int) {
		poc := selectedPOC()
		if poc == nil || index < 0 || index >= len(poc.Steps) {
			currentStepIndex = -1
			clearStepForm()
			return
		}

		stepSelectionGuard = true
		currentStepIndex = index
		step := poc.Steps[index]
		stepNameEntry.SetText(step.Name)
		methodSelect.SetSelected(step.Method)
		pathEntry.SetText(step.Path)
		paramsEntry.SetText(step.Params)
		bodyTypeSelect.SetSelected(step.BodyType)
		bodyEntry.SetText(step.Body)
		headersEntry.SetText(step.Headers)
		matchEntry.SetText(step.MatchRule)
		extractEntry.SetText(step.ExtractRules)
		continueCheck.SetChecked(step.ContinueOnError)
		if index < len(stepSelect.Options) {
			stepSelect.SetSelected(stepSelect.Options[index])
		}
		stepSelectionGuard = false
	}

	refreshStepEditor := func(selectIndex int) {
		poc := selectedPOC()
		if poc == nil {
			currentStepIndex = -1
			setStepSelectOptions(nil)
			clearStepForm()
			setStepFieldsEnabled(false)
			return
		}

		options := make([]string, 0, len(poc.Steps))
		for index, step := range poc.Steps {
			options = append(options, stepOptionLabel(index, step))
		}
		setStepSelectOptions(options)
		setStepFieldsEnabled(true)
		if len(options) == 0 {
			currentStepIndex = -1
			clearStepForm()
			return
		}

		if selectIndex < 0 || selectIndex >= len(options) {
			selectIndex = 0
		}
		loadStepToForm(selectIndex)
	}

	stepSelect.OnChanged = func(selected string) {
		if stepSelectionGuard || selected == "" {
			return
		}

		if !syncCurrentStepFromForm() {
			return
		}

		dotIndex := strings.Index(selected, ".")
		if dotIndex <= 0 {
			return
		}
		index, err := strconv.Atoi(strings.TrimSpace(selected[:dotIndex]))
		if err != nil || index <= 0 {
			return
		}
		loadStepToForm(index - 1)
	}

	clearEditor := func() {
		nodeNameEntry.SetText("")
		selectedLabel.SetText("当前未选择节点")
		setStepSelectOptions(nil)
		clearStepForm()
	}

	loadNodeToEditor := func(nodeID string) {
		currentSelectedID = nodeID
		if nodeID == "" {
			nodeNameEntry.Disable()
			saveBtn.Disable()
			setStepFieldsEnabled(false)
			clearEditor()
			return
		}

		node, ok := data.Nodes[nodeID]
		if !ok {
			nodeNameEntry.Disable()
			saveBtn.Disable()
			setStepFieldsEnabled(false)
			clearEditor()
			return
		}

		selectedLabel.SetText(fmt.Sprintf("当前节点：%s", node.Name))
		nodeNameEntry.Enable()
		saveBtn.Enable()
		nodeNameEntry.SetText(node.Name)

		if node.IsGroup {
			setStepFieldsEnabled(false)
			setStepSelectOptions(nil)
			clearStepForm()
			return
		}

		if node.Data == nil {
			node.Data = &POC{Name: node.Name, Steps: []RequestStep{defaultRequestStep("步骤 1")}}
		}
		node.Data.normalize()
		refreshStepEditor(0)
	}

	persistData := func(successMessage string) bool {
		if err := saveDataToFile(dataFile, data); err != nil {
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
		} else {
			singleTestBtn.Enable()
			batchTestBtn.Enable()
		}
		statusLabel.SetText(status)
	}

	startRunUI := func(total int, status string) {
		currentSummary = runSummary{Total: total}
		updateSummaryUI(currentSummary)
		setRunningStateUI(true, status)
	}

	finishRunUI := func(status string) {
		setRunningStateUI(false, status)
	}

	applyResultUI := func(result ExploitResult) {
		currentSummary.Done++
		if result.Level == "VULN" {
			currentSummary.Vuln++
		}
		if result.Level == "ERR" {
			currentSummary.Err++
		}
		updateSummaryUI(currentSummary)

		for _, stepResult := range result.StepResults {
			appendLogUI(stepResult.Level, stepResult.Message)
		}
		appendLogUI(result.Level, result.Message)
	}

	var matchesFilter func(string, string) bool
	matchesFilter = func(nodeID, keyword string) bool {
		node, ok := data.Nodes[nodeID]
		if !ok {
			return false
		}
		if keyword == "" || strings.Contains(strings.ToLower(node.Name), keyword) {
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
		if !syncCurrentStepFromForm() {
			return
		}
		loadNodeToEditor(id)
	}

	filterEntry.OnChanged = func(_ string) {
		tree.Refresh()
	}

	resolveImportParentID := func() string {
		if currentSelectedID == "" {
			return ""
		}
		node, ok := data.Nodes[currentSelectedID]
		if !ok {
			return ""
		}
		if node.IsGroup {
			return currentSelectedID
		}
		return node.ParentID
	}

	appendImportedPOCs := func(parentID, folderName string, pocs []POC) error {
		groupNode, err := data.addGroup(parentID, folderName)
		if err != nil {
			return err
		}
		for _, poc := range pocs {
			pocCopy := poc
			if _, err := data.addPOC(groupNode.ID, &pocCopy); err != nil {
				return err
			}
		}
		tree.Refresh()
		tree.Select(groupNode.ID)
		return nil
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

		parentID := resolveImportParentID()
		if parentID == "" {
			dialog.ShowInformation("提示", "请先选择一个文件夹", w)
			return
		}

		newNode, err := data.addPOC(parentID, &POC{
			Name:  "新建POC",
			Steps: []RequestStep{defaultRequestStep("步骤 1")},
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

		dialog.NewConfirm("确认删除", fmt.Sprintf("确定删除“%s”及其所有子节点吗？", node.Name), func(ok bool) {
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
		}, w).Show()
	})

	addStepBtn.OnTapped = func() {
		if !syncCurrentStepFromForm() {
			return
		}
		poc := selectedPOC()
		if poc == nil {
			return
		}
		poc.Steps = append(poc.Steps, defaultRequestStep(fmt.Sprintf("步骤 %d", len(poc.Steps)+1)))
		poc.normalize()
		refreshStepEditor(len(poc.Steps) - 1)
	}

	duplicateStepBtn.OnTapped = func() {
		if !syncCurrentStepFromForm() {
			return
		}
		poc := selectedPOC()
		if poc == nil || currentStepIndex < 0 || currentStepIndex >= len(poc.Steps) {
			return
		}
		clone := poc.Steps[currentStepIndex]
		clone.Name = clone.Name + " - 副本"
		insertAt := currentStepIndex + 1
		poc.Steps = append(poc.Steps[:insertAt], append([]RequestStep{clone}, poc.Steps[insertAt:]...)...)
		poc.normalize()
		refreshStepEditor(insertAt)
	}

	removeStepBtn.OnTapped = func() {
		poc := selectedPOC()
		if poc == nil || currentStepIndex < 0 || currentStepIndex >= len(poc.Steps) {
			return
		}
		if len(poc.Steps) == 1 {
			dialog.ShowInformation("提示", "至少保留一个请求步骤", w)
			return
		}
		poc.Steps = append(poc.Steps[:currentStepIndex], poc.Steps[currentStepIndex+1:]...)
		poc.normalize()
		refreshStepEditor(maxInt(0, currentStepIndex-1))
	}

	exportBtn := widget.NewButtonWithIcon("导出 JSON", theme.DownloadIcon(), func() {
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
			appendLogUI("INFO", "JSON 数据导出成功")
			statusLabel.SetText("JSON 数据导出成功")
		}, w)
		saveDialog.SetFileName("poc_data_backup.json")
		saveDialog.Show()
	})

	importJSONBtn := widget.NewButtonWithIcon("导入 JSON", theme.UploadIcon(), func() {
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

			dialog.NewConfirm("导入确认", "导入会覆盖当前内存中的所有节点，是否继续？", func(ok bool) {
				if !ok {
					return
				}
				data = importedData
				filterEntry.SetText("")
				tree.UnselectAll()
				tree.Refresh()
				loadNodeToEditor("")
				_ = persistData("JSON 数据已导入并保存")
			}, w).Show()
		}, w)
		openDialog.SetFilter(storage.NewExtensionFileFilter([]string{".json"}))
		openDialog.Show()
	})

	importNucleiBtn := widget.NewButtonWithIcon("导入 Nuclei", theme.DownloadIcon(), func() {
		if isRunning {
			appendLogUI("INFO", "当前正在执行验证，请等待完成后再导入模板")
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

			folderName, importedPOCs, err := importNucleiTemplate(reader)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if len(importedPOCs) == 0 {
				dialog.ShowInformation("提示", "模板未解析出可导入的 POC", w)
				return
			}

			if err := appendImportedPOCs(resolveImportParentID(), folderName, importedPOCs); err != nil {
				dialog.ShowError(err, w)
				return
			}
			_ = persistData(fmt.Sprintf("已导入 Nuclei 模板，共 %d 个 POC", len(importedPOCs)))
		}, w)
		openDialog.SetFilter(storage.NewExtensionFileFilter([]string{".yaml", ".yml"}))
		openDialog.Show()
	})

	saveBtn.OnTapped = func() {
		if currentSelectedID == "" {
			dialog.ShowInformation("提示", "请先选择一个节点", w)
			return
		}
		if !syncCurrentStepFromForm() {
			return
		}

		node, ok := data.Nodes[currentSelectedID]
		if !ok {
			dialog.ShowError(fmt.Errorf("当前节点不存在"), w)
			return
		}

		nodeName := strings.TrimSpace(nodeNameEntry.Text)
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
			node.Data = &POC{Name: nodeName, Steps: []RequestStep{defaultRequestStep("步骤 1")}}
		}
		node.Data.Name = nodeName
		node.Data.normalize()
		tree.Refresh()
		_ = persistData("POC 已保存")
	}

	singleTestBtn.OnTapped = func() {
		if isRunning {
			return
		}
		if !syncCurrentStepFromForm() {
			return
		}

		targetBase := strings.TrimSpace(targetEntry.Text)
		if targetBase == "" {
			appendLogUI("ERR", "请输入目标地址")
			return
		}
		poc := selectedPOC()
		if poc == nil {
			appendLogUI("ERR", "请先选择一个有效的 POC 节点")
			return
		}

		settings, _, err := parseRunSettings()
		if err != nil {
			appendLogUI("ERR", err.Error())
			return
		}

		pocCopy := clonePOC(poc)
		appendLogUI("INFO", fmt.Sprintf("=== 开始单点验证：%s ===", pocCopy.Name))
		startRunUI(1, "单点验证进行中")

		go func() {
			result := runner.Run(targetBase, pocCopy, settings)
			fyne.Do(func() {
				applyResultUI(result)
				appendLogUI("INFO", "=== 单点验证完成 ===")
				finishRunUI("单点验证完成")
			})
		}()
	}

	batchTestBtn.OnTapped = func() {
		if isRunning {
			return
		}
		if !syncCurrentStepFromForm() {
			return
		}

		targetBase := strings.TrimSpace(targetEntry.Text)
		if targetBase == "" {
			appendLogUI("ERR", "请输入目标地址")
			return
		}
		if currentSelectedID == "" {
			appendLogUI("ERR", "请先选择测试范围")
			return
		}

		targets := data.collectPOCs(currentSelectedID)
		if len(targets) == 0 {
			appendLogUI("INFO", "当前范围内没有可执行的 POC")
			return
		}

		scopeName := currentSelectedID
		if node, ok := data.Nodes[currentSelectedID]; ok {
			scopeName = node.Name
		}

		settings, concurrency, err := parseRunSettings()
		if err != nil {
			appendLogUI("ERR", err.Error())
			return
		}

		appendLogUI("INFO", fmt.Sprintf("=== 开始批量验证：%s，共 %d 条，%d 并发 ===", scopeName, len(targets), concurrency))
		startRunUI(len(targets), fmt.Sprintf("批量验证进行中（%d 条）", len(targets)))

		go func() {
			workerCount := minInt(concurrency, len(targets))
			jobs := make(chan *POC)
			results := make(chan ExploitResult)
			var wg sync.WaitGroup

			for i := 0; i < workerCount; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for poc := range jobs {
						results <- runner.Run(targetBase, poc, settings)
					}
				}()
			}

			go func() {
				for _, poc := range targets {
					jobs <- poc
				}
				close(jobs)
				wg.Wait()
				close(results)
			}()

			for result := range results {
				resultCopy := result
				fyne.Do(func() {
					applyResultUI(resultCopy)
					statusLabel.SetText(fmt.Sprintf("批量验证中 %d/%d", currentSummary.Done, currentSummary.Total))
				})
			}

			fyne.Do(func() {
				appendLogUI("INFO", fmt.Sprintf("=== 批量验证完成：命中 %d，错误 %d ===", currentSummary.Vuln, currentSummary.Err))
				finishRunUI("批量验证完成")
			})
		}()
	}

	toolBar := container.NewGridWithColumns(3, addFolderBtn, addPOCBtn, deleteBtn)
	dataBar := container.NewGridWithColumns(3, exportBtn, importJSONBtn, importNucleiBtn)

	leftCard := widget.NewCard(
		"POC 目录",
		"支持名称筛选与 Nuclei 模板导入",
		container.NewBorder(
			container.NewVBox(filterEntry, toolBar, widget.NewSeparator()),
			container.NewVBox(widget.NewSeparator(), dataBar),
			nil,
			nil,
			container.NewPadded(tree),
		),
	)

	stepToolbar := container.NewGridWithColumns(4,
		widget.NewForm(widget.NewFormItem("当前步骤", stepSelect)),
		addStepBtn,
		duplicateStepBtn,
		removeStepBtn,
	)

	stepForm := widget.NewForm(
		widget.NewFormItem("节点名称", nodeNameEntry),
		widget.NewFormItem("步骤名称", stepNameEntry),
		widget.NewFormItem("请求方法", methodSelect),
		widget.NewFormItem("路径", pathEntry),
		widget.NewFormItem("查询参数", paramsEntry),
		widget.NewFormItem("Body 类型", bodyTypeSelect),
		widget.NewFormItem("Body", bodyScroll),
		widget.NewFormItem("Headers", headersScroll),
		widget.NewFormItem("匹配规则", matchEntry),
		widget.NewFormItem("变量提取", extractScroll),
		widget.NewFormItem("步骤策略", continueCheck),
	)

	editorCard := widget.NewCard(
		"链式 POC 编辑器",
		"支持多步骤请求、变量提取与占位符替换",
		container.NewVBox(
			selectedLabel,
			stepToolbar,
			widget.NewSeparator(),
			stepForm,
			container.NewHBox(layout.NewSpacer(), saveBtn),
		),
	)

	summaryGrid := container.NewGridWithColumns(
		4,
		widget.NewCard("总数", "", totalValue),
		widget.NewCard("已完成", "", doneValue),
		widget.NewCard("命中", "", vulnValue),
		widget.NewCard("错误", "", errValue),
	)

	logCard := widget.NewCard(
		"运行日志",
		"链式步骤日志、结果汇总与自动裁剪",
		container.NewBorder(
			container.NewVBox(summaryGrid, progressBar, widget.NewSeparator()),
			container.NewHBox(layout.NewSpacer(), clearLogBtn),
			nil,
			nil,
			logScroll,
		),
	)

	rightPanel := container.NewVSplit(container.NewPadded(editorCard), container.NewPadded(logCard))
	rightPanel.SetOffset(0.60)

	mainSplit := container.NewHSplit(container.NewPadded(leftCard), container.NewPadded(rightPanel))
	mainSplit.SetOffset(0.28)

	topCard := widget.NewCard(
		"目标与运行选项",
		"支持超时、TLS、批量并发和链式请求验证",
		container.NewVBox(
			targetEntry,
			container.NewGridWithColumns(
				4,
				widget.NewForm(widget.NewFormItem("超时(秒)", timeoutEntry)),
				widget.NewForm(widget.NewFormItem("批量并发", concurrencySelect)),
				container.NewCenter(insecureTLSCheck),
				container.NewGridWithColumns(2, singleTestBtn, batchTestBtn),
			),
		),
	)

	statusBar := container.NewBorder(
		nil,
		nil,
		widget.NewLabelWithStyle("状态", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nil,
		statusLabel,
	)

	content := container.NewBorder(
		container.NewPadded(topCard),
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
		if !syncCurrentStepFromForm() {
			return
		}
		if err := saveDataToFile(dataFile, data); err != nil {
			dialog.ShowError(err, w)
			return
		}
		w.Close()
	})

	w.SetContent(content)
	w.ShowAndRun()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
