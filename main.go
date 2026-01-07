package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// --- 1. 核心数据结构 ---

type POC struct {
	Name      string
	Method    string
	Path      string
	Params    string
	Body      string
	BodyType  string
	Headers   string
	MatchRule string
}

type Node struct {
	ID       string
	ParentID string
	Name     string
	IsGroup  bool
	Children []string
	Data     *POC
}

// --- 2. 全局状态管理 ---

var (
	nodeMap   map[string]*Node // 修改为变量声明，但不初始化
	rootIDs   []string
	idCounter int
)

const dataFile = "poc_data.json"

func init() {
	// 在 init 函数中初始化全局变量
	nodeMap = make(map[string]*Node)
}

func generateID() string {
	idCounter++
	return strconv.Itoa(idCounter)
}

// --- 3. 数据持久化 ---

func saveData() error {
	data := struct {
		Nodes   map[string]*Node
		RootIDs []string
		Counter int
	}{
		Nodes:   nodeMap,
		RootIDs: rootIDs,
		Counter: idCounter,
	}

	file, err := os.Create(dataFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func loadData() error {
	file, err := os.Open(dataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	var data struct {
		Nodes   map[string]*Node
		RootIDs []string
		Counter int
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return err
	}

	// 确保 nodeMap 已初始化
	if nodeMap == nil {
		nodeMap = make(map[string]*Node)
	}

	// 清空现有数据，然后加载新数据
	for k := range nodeMap {
		delete(nodeMap, k)
	}

	// 加载新的节点
	for k, v := range data.Nodes {
		nodeMap[k] = v
	}

	rootIDs = data.RootIDs
	idCounter = data.Counter
	return nil
}

func initDefaultData() {
	// 确保 nodeMap 已初始化
	if nodeMap == nil {
		nodeMap = make(map[string]*Node)
	}

	// 清空现有数据
	for k := range nodeMap {
		delete(nodeMap, k)
	}
	rootIDs = []string{}
	idCounter = 0

	rootID := generateID()
	rootNode := &Node{
		ID:       rootID,
		Name:     "用友 U8 Cloud",
		IsGroup:  true,
		Children: []string{},
	}
	nodeMap[rootID] = rootNode
	rootIDs = append(rootIDs, rootID)

	catID := generateID()
	catNode := &Node{
		ID:       catID,
		ParentID: rootID,
		Name:     "SQL 注入漏洞",
		IsGroup:  true,
		Children: []string{},
	}
	nodeMap[catID] = catNode
	rootNode.Children = append(rootNode.Children, catID)

	poc1ID := generateID()
	poc1 := &POC{
		Name:      "KeyWord-SQL注入",
		Method:    "POST",
		Path:      "/service/monitorservlet",
		Body:      "key=1' OR 1=1--",
		BodyType:  "Form",
		MatchRule: "SQL syntax",
	}
	nodeMap[poc1ID] = &Node{
		ID:       poc1ID,
		ParentID: catID,
		Name:     poc1.Name,
		IsGroup:  false,
		Data:     poc1,
	}
	catNode.Children = append(catNode.Children, poc1ID)

	poc2ID := generateID()
	poc2 := &POC{
		Name:      "Login-Bypass",
		Method:    "GET",
		Path:      "/admin/index.jsp",
		Params:    "bypass=true",
		MatchRule: "Welcome Admin",
	}
	nodeMap[poc2ID] = &Node{
		ID:       poc2ID,
		ParentID: catID,
		Name:     poc2.Name,
		IsGroup:  false,
		Data:     poc2,
	}
	catNode.Children = append(catNode.Children, poc2ID)
}

// --- 4. 核心逻辑 ---

func collectPOCs(nodeID string) []*POC {
	if nodeMap == nil {
		return nil
	}

	node, exists := nodeMap[nodeID]
	if !exists {
		return nil
	}

	var results []*POC
	if !node.IsGroup {
		if node.Data != nil {
			results = append(results, node.Data)
		}
	} else {
		for _, childID := range node.Children {
			results = append(results, collectPOCs(childID)...)
		}
	}
	return results
}

func sendExploit(targetBase string, poc *POC, logFunc func(string, string)) {
	if targetBase == "" {
		logFunc("ERR", "目标地址为空")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	targetBase = strings.TrimRight(targetBase, "/")
	path := strings.TrimLeft(poc.Path, "/")
	fullURL := fmt.Sprintf("%s/%s", targetBase, path)

	if poc.Params != "" {
		if strings.Contains(fullURL, "?") {
			fullURL += "&" + poc.Params
		} else {
			fullURL += "?" + poc.Params
		}
	}

	var bodyReader io.Reader
	if poc.Method != "GET" && poc.Body != "" {
		bodyReader = bytes.NewBufferString(poc.Body)
	}

	req, err := http.NewRequestWithContext(ctx, poc.Method, fullURL, bodyReader)
	if err != nil {
		logFunc("ERR", fmt.Sprintf("[%s] 请求构造失败: %v", poc.Name, err))
		return
	}

	if poc.Method == "POST" || poc.Method == "PUT" {
		if poc.BodyType == "JSON" {
			req.Header.Set("Content-Type", "application/json")
		} else if poc.BodyType == "Form" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Go-Exploit-Tool)")

	if poc.Headers != "" {
		lines := strings.Split(poc.Headers, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 跳过证书验证
			},
		},
	}

	logFunc("INFO", fmt.Sprintf("正在测试: %s [%s %s]", poc.Name, poc.Method, poc.Path))
	resp, err := client.Do(req)
	if err != nil {
		logFunc("ERR", fmt.Sprintf("请求失败: %v", err))
		return
	}
	defer resp.Body.Close()

	maxBytes := int64(1024 * 1024)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		logFunc("ERR", fmt.Sprintf("读取响应失败: %v", err))
		return
	}
	respStr := string(respBody)

	if poc.MatchRule != "" && strings.Contains(respStr, poc.MatchRule) {
		logFunc("VULN", fmt.Sprintf("[+] 发现漏洞: %s (Status: %d)", poc.Name, resp.StatusCode))
	} else {
		logFunc("SAFE", fmt.Sprintf("[-] 未命中: %s (Status: %d)", poc.Name, resp.StatusCode))
	}
}

func deleteNodeAndChildren(nodeID string) {
	if nodeMap == nil {
		return
	}

	node, ok := nodeMap[nodeID]
	if !ok {
		return
	}

	for _, childID := range node.Children {
		deleteNodeAndChildren(childID)
	}

	delete(nodeMap, nodeID)
}

// --- 5. GUI 主程序 ---

func main() {
	// 确保全局变量已初始化
	if nodeMap == nil {
		nodeMap = make(map[string]*Node)
	}

	if err := loadData(); err != nil {
		fmt.Printf("加载数据失败，使用默认数据: %v\n", err)
		initDefaultData()
	}

	a := app.New()
	w := a.NewWindow("ALL1n-通用POC渗透测试框架")
	w.Resize(fyne.NewSize(1200, 800))

	// --- 顶部目标输入和测试按钮 ---
	targetEntry := widget.NewEntry()
	targetEntry.SetPlaceHolder("目标地址 (e.g., http://192.168.131.130:8080)")

	singleTestBtn := widget.NewButtonWithIcon("单点测试", theme.MediaPlayIcon(), nil)
	batchTestBtn := widget.NewButtonWithIcon("一键测试(选中大文件夹中的POC)", theme.MediaSkipNextIcon(), nil)

	topPanel := container.NewVBox(
		widget.NewLabelWithStyle("测试目标", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		targetEntry,
		container.NewHBox(singleTestBtn, batchTestBtn),
		widget.NewSeparator(),
	)

	// --- 日志组件 ---
	richLog := widget.NewRichText()
	logScroll := container.NewVScroll(richLog)
	logScroll.SetMinSize(fyne.NewSize(0, 200))

	appendLog := func(lvl, msg string) {
		col := theme.ColorNameForeground
		switch lvl {
		case "VULN":
			col = theme.ColorNameSuccess
		case "ERR":
			col = theme.ColorNameError
		case "INFO":
			col = theme.ColorNamePrimary
		}
		timeStr := time.Now().Format("15:04:05")
		richLog.Segments = append(richLog.Segments,
			&widget.TextSegment{Text: timeStr + " ", Style: widget.RichTextStyle{ColorName: theme.ColorNameDisabled}},
			&widget.TextSegment{Text: "[" + lvl + "] " + msg + "\n", Style: widget.RichTextStyle{ColorName: col, TextStyle: fyne.TextStyle{Monospace: true}}},
		)
		richLog.Refresh()
		logScroll.ScrollToBottom()
	}

	// --- 编辑器组件 ---
	var currentSelectedID string

	nameEntry := widget.NewEntry()
	methodSelect := widget.NewSelect([]string{"GET", "POST", "PUT", "DELETE"}, nil)
	pathEntry := widget.NewEntry()
	pathEntry.SetPlaceHolder("/api/v1/login")
	paramsEntry := widget.NewEntry()
	paramsEntry.SetPlaceHolder("id=1&debug=true")
	bodyTypeSelect := widget.NewSelect([]string{"Raw", "JSON", "Form"}, nil)

	bodyEntry := widget.NewMultiLineEntry()
	bodyEntry.Wrapping = fyne.TextWrapWord
	bodyScroll := container.NewScroll(bodyEntry)
	bodyScroll.SetMinSize(fyne.NewSize(0, 100))

	headersEntry := widget.NewMultiLineEntry()
	headersEntry.SetPlaceHolder("Cookie: user=admin\nX-Token: 123")
	headersEntry.Wrapping = fyne.TextWrapWord
	headersScroll := container.NewScroll(headersEntry)
	headersScroll.SetMinSize(fyne.NewSize(0, 80))

	matchEntry := widget.NewEntry()
	matchEntry.SetPlaceHolder("响应中包含此字符串则判定成功")

	saveBtn := widget.NewButtonWithIcon("保存", theme.DocumentSaveIcon(), nil)

	// --- 树形列表 ---
	var tree *widget.Tree

	tree = widget.NewTree(
		func(id widget.TreeNodeID) []widget.TreeNodeID {
			if id == "" {
				return rootIDs
			}
			node, ok := nodeMap[id]
			if !ok {
				return nil
			}
			return node.Children
		},
		func(id widget.TreeNodeID) bool {
			if id == "" {
				return true
			}
			node, ok := nodeMap[id]
			if !ok {
				return false
			}
			return node.IsGroup
		},
		func(branch bool) fyne.CanvasObject {
			if branch {
				return container.NewHBox(widget.NewIcon(theme.FolderIcon()), widget.NewLabel("Folder"))
			}
			return container.NewHBox(widget.NewIcon(theme.FileIcon()), widget.NewLabel("POC"))
		},
		func(id widget.TreeNodeID, branch bool, o fyne.CanvasObject) {
			node, ok := nodeMap[id]
			if !ok {
				return
			}
			lbl := o.(*fyne.Container).Objects[1].(*widget.Label)
			lbl.SetText(node.Name)
		},
	)

	// --- 树节点操作 ---
	tree.OnSelected = func(id widget.TreeNodeID) {
		currentSelectedID = id
		node := nodeMap[id]

		nameEntry.SetText(node.Name)
		if !node.IsGroup && node.Data != nil {
			methodSelect.SetSelected(node.Data.Method)
			pathEntry.SetText(node.Data.Path)
			paramsEntry.SetText(node.Data.Params)
			bodyEntry.SetText(node.Data.Body)
			bodyTypeSelect.SetSelected(node.Data.BodyType)
			headersEntry.SetText(node.Data.Headers)
			matchEntry.SetText(node.Data.MatchRule)

			pathEntry.Enable()
			bodyEntry.Enable()
			headersEntry.Enable()
			matchEntry.Enable()
		} else {
			methodSelect.ClearSelected()
			pathEntry.SetText("")
			paramsEntry.SetText("")
			bodyEntry.SetText("")
			bodyTypeSelect.ClearSelected()
			headersEntry.SetText("")
			matchEntry.SetText("")

			pathEntry.Disable()
			bodyEntry.Disable()
			headersEntry.Disable()
			matchEntry.Disable()
		}
	}

	// --- 树操作按钮 ---
	treeToolbar := container.NewHBox(
		widget.NewButtonWithIcon("新建文件夹", theme.FolderNewIcon(), func() {
			// 确保 nodeMap 已初始化
			if nodeMap == nil {
				nodeMap = make(map[string]*Node)
			}

			newID := generateID()
			newNode := &Node{
				ID:       newID,
				Name:     "新建文件夹",
				IsGroup:  true,
				Children: []string{},
			}

			nodeMap[newID] = newNode

			if currentSelectedID == "" {
				rootIDs = append(rootIDs, newID)
			} else {
				parent, ok := nodeMap[currentSelectedID]
				if !ok {
					dialog.ShowError(fmt.Errorf("父节点不存在"), w)
					return
				}
				if !parent.IsGroup {
					dialog.ShowError(fmt.Errorf("不能在POC下添加子节点，请选择文件夹"), w)
					return
				}
				newNode.ParentID = currentSelectedID
				parent.Children = append(parent.Children, newID)
			}
			tree.Refresh()
			if err := saveData(); err != nil {
				dialog.ShowError(err, w)
			}
		}),
		widget.NewButtonWithIcon("新建POC", theme.FileIcon(), func() {
			// 确保 nodeMap 已初始化
			if nodeMap == nil {
				nodeMap = make(map[string]*Node)
			}

			if currentSelectedID == "" {
				dialog.ShowError(fmt.Errorf("请先选择一个文件夹"), w)
				return
			}

			parent, ok := nodeMap[currentSelectedID]
			if !ok {
				dialog.ShowError(fmt.Errorf("选择的文件夹不存在"), w)
				return
			}

			if !parent.IsGroup {
				dialog.ShowError(fmt.Errorf("请选择一个文件夹来添加POC"), w)
				return
			}

			newID := generateID()
			newPOC := &POC{
				Name:     "新建POC",
				Method:   "GET",
				Path:     "/",
				BodyType: "Raw",
			}
			newNode := &Node{
				ID:       newID,
				ParentID: currentSelectedID,
				Name:     newPOC.Name,
				IsGroup:  false,
				Data:     newPOC,
			}

			nodeMap[newID] = newNode
			parent.Children = append(parent.Children, newID)

			tree.Refresh()
			if err := saveData(); err != nil {
				dialog.ShowError(err, w)
			}
		}),
		widget.NewButtonWithIcon("删除", theme.DeleteIcon(), func() {
			if currentSelectedID == "" {
				dialog.ShowInformation("提示", "请先选择一个节点", w)
				return
			}

			node := nodeMap[currentSelectedID]

			confirm := dialog.NewConfirm("确认删除",
				fmt.Sprintf("确定要删除 '%s' 吗？", node.Name),
				func(ok bool) {
					if !ok {
						return
					}

					if node.ParentID != "" {
						if parent, ok := nodeMap[node.ParentID]; ok {
							newChildren := []string{}
							for _, childID := range parent.Children {
								if childID != currentSelectedID {
									newChildren = append(newChildren, childID)
								}
							}
							parent.Children = newChildren
						}
					} else {
						newRootIDs := []string{}
						for _, rootID := range rootIDs {
							if rootID != currentSelectedID {
								newRootIDs = append(newRootIDs, rootID)
							}
						}
						rootIDs = newRootIDs
					}

					deleteNodeAndChildren(currentSelectedID)
					currentSelectedID = ""

					nameEntry.SetText("")
					methodSelect.ClearSelected()
					pathEntry.SetText("")
					paramsEntry.SetText("")
					bodyEntry.SetText("")
					bodyTypeSelect.ClearSelected()
					headersEntry.SetText("")
					matchEntry.SetText("")

					tree.Refresh()
					if err := saveData(); err != nil {
						dialog.ShowError(err, w)
					}
				}, w)
			confirm.Show()
		}),
	)

	// --- 数据管理按钮 ---
	dataToolbar := container.NewHBox(
		widget.NewButtonWithIcon("导出", theme.DownloadIcon(), func() {
			saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
				if err != nil || writer == nil {
					return
				}
				defer writer.Close()

				encoder := json.NewEncoder(writer)
				encoder.SetIndent("", "  ")
				data := struct {
					Nodes   map[string]*Node
					RootIDs []string
					Counter int
				}{
					Nodes:   nodeMap,
					RootIDs: rootIDs,
					Counter: idCounter,
				}

				if err := encoder.Encode(data); err != nil {
					dialog.ShowError(err, w)
				} else {
					dialog.ShowInformation("成功", "数据已导出", w)
				}
			}, w)
			saveDialog.SetFileName("poc_data_backup.json")
			saveDialog.Show()
		}),
		widget.NewButtonWithIcon("导入", theme.UploadIcon(), func() {
			openDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
				if err != nil || reader == nil {
					return
				}
				defer reader.Close()

				var data struct {
					Nodes   map[string]*Node
					RootIDs []string
					Counter int
				}

				decoder := json.NewDecoder(reader)
				if err := decoder.Decode(&data); err != nil {
					dialog.ShowError(err, w)
					return
				}

				confirm := dialog.NewConfirm("导入确认",
					"导入将替换当前所有数据，是否继续？",
					func(ok bool) {
						if !ok {
							return
						}

						// 确保 nodeMap 已初始化
						if nodeMap == nil {
							nodeMap = make(map[string]*Node)
						} else {
							// 清空现有数据
							for k := range nodeMap {
								delete(nodeMap, k)
							}
						}

						// 加载新的数据
						for k, v := range data.Nodes {
							nodeMap[k] = v
						}

						rootIDs = data.RootIDs
						idCounter = data.Counter

						tree.Refresh()
						currentSelectedID = ""
						nameEntry.SetText("")
						methodSelect.ClearSelected()
						pathEntry.SetText("")
						paramsEntry.SetText("")
						bodyEntry.SetText("")
						bodyTypeSelect.ClearSelected()
						headersEntry.SetText("")
						matchEntry.SetText("")

						if err := saveData(); err != nil {
							dialog.ShowError(err, w)
						} else {
							dialog.ShowInformation("成功", "数据已导入并保存", w)
						}
					}, w)
				confirm.Show()
			}, w)
			openDialog.SetFilter(storage.NewExtensionFileFilter([]string{".json"}))
			openDialog.Show()
		}),
	)

	// --- 配置按钮事件 ---
	saveBtn.OnTapped = func() {
		if currentSelectedID == "" {
			dialog.ShowInformation("提示", "请先选择一个节点", w)
			return
		}
		node := nodeMap[currentSelectedID]
		if node.IsGroup {
			node.Name = nameEntry.Text
		} else {
			if node.Data == nil {
				node.Data = &POC{}
			}
			node.Name = nameEntry.Text
			node.Data.Name = nameEntry.Text
			node.Data.Method = methodSelect.Selected
			node.Data.Path = pathEntry.Text
			node.Data.Params = paramsEntry.Text
			node.Data.Body = bodyEntry.Text
			node.Data.BodyType = bodyTypeSelect.Selected
			node.Data.Headers = headersEntry.Text
			node.Data.MatchRule = matchEntry.Text
		}

		if err := saveData(); err != nil {
			dialog.ShowError(err, w)
		} else {
			dialog.ShowInformation("成功", "节点信息已保存", w)
			tree.Refresh()
		}
	}

	singleTestBtn.OnTapped = func() {
		if targetEntry.Text == "" {
			appendLog("ERR", "请输入Target URL")
			return
		}
		if currentSelectedID == "" {
			appendLog("ERR", "请先在左侧选择一个POC节点")
			return
		}

		node := nodeMap[currentSelectedID]
		if node.IsGroup {
			appendLog("ERR", "请选择一个具体的POC，而不是文件夹")
			return
		}

		if node.Data == nil {
			appendLog("ERR", "选中的节点没有POC数据")
			return
		}

		appendLog("INFO", fmt.Sprintf("=== 单点测试: %s ===", node.Data.Name))
		go func() {
			sendExploit(targetEntry.Text, node.Data, appendLog)
			appendLog("INFO", "=== 单点测试完成 ===")
		}()
	}

	batchTestBtn.OnTapped = func() {
		if targetEntry.Text == "" {
			appendLog("ERR", "请输入Target URL")
			return
		}
		if currentSelectedID == "" {
			appendLog("ERR", "请先在左侧选择测试范围")
			return
		}

		targets := collectPOCs(currentSelectedID)
		scopeName := nodeMap[currentSelectedID].Name

		if len(targets) == 0 {
			appendLog("INFO", "选中的范围内没有可测试的POC")
			return
		}

		appendLog("INFO", fmt.Sprintf("=== 开始批量测试: %s (包含 %d 个POC) ===", scopeName, len(targets)))

		go func() {
			for i, poc := range targets {
				appendLog("INFO", fmt.Sprintf("进度: %d/%d", i+1, len(targets)))
				sendExploit(targetEntry.Text, poc, appendLog)
				time.Sleep(200 * time.Millisecond)
			}
			appendLog("INFO", "=== 批量测试完成 ===")
		}()
	}

	// --- 清空日志按钮 ---
	clearLogBtn := widget.NewButtonWithIcon("清空日志", theme.DeleteIcon(), func() {
		richLog.Segments = nil
		richLog.Refresh()
	})

	// --- 布局组装 ---
	// 左侧面板：树和工具栏
	leftPanel := container.NewBorder(
		container.NewVBox(
			widget.NewLabelWithStyle("POC列表", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			treeToolbar,
			widget.NewSeparator(),
		),
		container.NewVBox(
			widget.NewSeparator(),
			dataToolbar,
		),
		nil, nil,
		container.NewBorder(nil, nil, nil, nil, tree),
	)

	// 编辑器表单
	formItems := []*widget.FormItem{
		widget.NewFormItem("名称", nameEntry),
		widget.NewFormItem("方法", methodSelect),
		widget.NewFormItem("路径", pathEntry),
		widget.NewFormItem("参数", paramsEntry),
		widget.NewFormItem("Body类型", bodyTypeSelect),
		widget.NewFormItem("Body", bodyScroll),
		widget.NewFormItem("Headers", headersScroll),
		widget.NewFormItem("匹配规则", matchEntry),
	}
	form := widget.NewForm(formItems...)

	// 编辑器面板
	editorPanel := container.NewVBox(
		widget.NewLabelWithStyle("POC编辑器", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		form,
		container.NewHBox(saveBtn),
	)
	editorScroll := container.NewScroll(editorPanel)

	// 日志面板
	logPanel := container.NewBorder(
		nil,
		container.NewHBox(
			clearLogBtn,
		),
		nil, nil,
		logScroll,
	)

	// 右侧面板：编辑器 + 日志
	rightPanel := container.NewVSplit(
		container.NewPadded(editorScroll),
		container.NewStack(
			canvas.NewRectangle(&color.RGBA{R: 30, G: 30, B: 30, A: 255}),
			container.NewPadded(logPanel),
		),
	)
	rightPanel.SetOffset(0.6)

	// 主布局
	mainSplit := container.NewHSplit(
		container.NewPadded(leftPanel),
		container.NewPadded(rightPanel),
	)
	mainSplit.SetOffset(0.25)

	// 整体布局
	content := container.NewBorder(
		container.NewPadded(topPanel),
		nil, nil, nil,
		mainSplit,
	)

	// 窗口关闭时保存数据
	w.SetCloseIntercept(func() {
		if err := saveData(); err != nil {
			fmt.Printf("保存数据失败: %v\n", err)
		}
		w.Close()
	})

	w.SetContent(content)
	w.ShowAndRun()
}
