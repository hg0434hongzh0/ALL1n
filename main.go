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
	w.Resize(fyne.NewSize(1360, 860))

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

		if summary.Total == 0 {
			progressBar.SetValue(0)
			return
		}
		progressBar.SetValue(float64(summary.Done) / float64(summary.Total))
	}

	currentSummary := runSummary{}
	isRunning := false

	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("节点名称")

	methodSelect := widget.NewSelect([]string{"GET", "POST", "PUT", "DELETE", "PATCH"}, nil)
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
	matchEntry.SetPlaceHolder("支持纯文本，或 body:/status:/header:/regex:，可用 && 组合")

	saveBtn := widget.NewButtonWithIcon("保存节点", theme.DocumentSaveIcon(), nil)
	clearLogBtn := widget.NewButtonWithIcon("清空日志", theme.DeleteIcon(), func() {
		logEntries = logEntries[:0]
		refreshLog()
		statusLabel.SetText("日志已清空")
	})
	singleTestBtn := widget.NewButtonWithIcon("单点验证", theme.MediaPlayIcon(), nil)
	batchTestBtn := widget.NewButtonWithIcon("批量验证", theme.MediaSkipNextIcon(), nil)

	var currentSelectedID string
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

	loadNodeToEditor := func(nodeID string) {
		currentSelectedID = nodeID
		if nodeID == "" {
			selectedLabel.SetText("当前未选择节点")
			nameEntry.Disable()
			setPOCFieldsEnabled(false)
			saveBtn.Disable()
			clearEditor()
			return
		}

		node, ok := data.Nodes[nodeID]
		if !ok {
			selectedLabel.SetText("当前节点不存在")
			nameEntry.Disable()
			setPOCFieldsEnabled(false)
			saveBtn.Disable()
			clearEditor()
			return
		}

		selectedLabel.SetText(fmt.Sprintf("当前节点：%s", node.Name))
		nameEntry.Enable()
		saveBtn.Enable()
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
		appendLogUI(result.Level, result.Message)
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

	singleTestBtn.OnTapped = func() {
		if isRunning {
			return
		}

		targetBase := strings.TrimSpace(targetEntry.Text)
		if targetBase == "" {
			appendLogUI("ERR", "请输入目标地址")
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

		settings, _, err := parseRunSettings()
		if err != nil {
			appendLogUI("ERR", err.Error())
			return
		}

		poc := clonePOC(node.Data)
		appendLogUI("INFO", fmt.Sprintf("=== 开始单点验证：%s ===", poc.Name))
		startRunUI(1, "单点验证进行中")

		go func() {
			result := runner.Run(targetBase, poc, settings)
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
			workerCount := concurrency
			if workerCount > len(targets) {
				workerCount = len(targets)
			}

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
	dataBar := container.NewGridWithColumns(2, exportBtn, importBtn)

	leftCard := widget.NewCard(
		"POC 目录",
		"支持按名称快速筛选",
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

	editorCard := widget.NewCard(
		"POC 编辑器",
		"更清晰的字段分组与状态控制",
		container.NewVBox(
			selectedLabel,
			form,
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
		"日志自动裁剪，避免长时间运行占满界面",
		container.NewBorder(
			container.NewVBox(summaryGrid, progressBar, widget.NewSeparator()),
			container.NewHBox(layout.NewSpacer(), clearLogBtn),
			nil,
			nil,
			logScroll,
		),
	)

	rightPanel := container.NewVSplit(
		container.NewPadded(editorCard),
		container.NewPadded(logCard),
	)
	rightPanel.SetOffset(0.56)

	mainSplit := container.NewHSplit(
		container.NewPadded(leftCard),
		container.NewPadded(rightPanel),
	)
	mainSplit.SetOffset(0.28)

	topCard := widget.NewCard(
		"目标与运行选项",
		"支持超时、TLS 策略和批量并发数控制",
		container.NewVBox(
			targetEntry,
			container.NewGridWithColumns(
				4,
				widget.NewForm(
					widget.NewFormItem("超时(秒)", timeoutEntry),
				),
				widget.NewForm(
					widget.NewFormItem("批量并发", concurrencySelect),
				),
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
		if err := saveDataToFile(dataFile, data); err != nil {
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
