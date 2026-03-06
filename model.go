package main

import (
	"fmt"
	"strconv"
	"strings"
)

type RequestStep struct {
	Name            string `json:"name"`
	Method          string `json:"method"`
	Path            string `json:"path"`
	Params          string `json:"params"`
	Body            string `json:"body"`
	BodyType        string `json:"body_type"`
	Headers         string `json:"headers"`
	MatchRule       string `json:"match_rule"`
	ExtractRules    string `json:"extract_rules,omitempty"`
	ContinueOnError bool   `json:"continue_on_error,omitempty"`
}

type POC struct {
	Name      string        `json:"name"`
	Method    string        `json:"method,omitempty"`
	Path      string        `json:"path,omitempty"`
	Params    string        `json:"params,omitempty"`
	Body      string        `json:"body,omitempty"`
	BodyType  string        `json:"body_type,omitempty"`
	Headers   string        `json:"headers,omitempty"`
	MatchRule string        `json:"match_rule,omitempty"`
	Steps     []RequestStep `json:"steps,omitempty"`
}

type Node struct {
	ID       string   `json:"id"`
	ParentID string   `json:"parent_id"`
	Name     string   `json:"name"`
	IsGroup  bool     `json:"is_group"`
	Children []string `json:"children"`
	Data     *POC     `json:"data,omitempty"`
}

type appData struct {
	Nodes   map[string]*Node `json:"nodes"`
	RootIDs []string         `json:"root_ids"`
	Counter int              `json:"counter"`
}

func newAppData() *appData {
	return &appData{
		Nodes:   make(map[string]*Node),
		RootIDs: []string{},
	}
}

func defaultAppData() *appData {
	data := newAppData()

	rootNode, _ := data.addGroup("", "用友 U8 Cloud")
	categoryNode, _ := data.addGroup(rootNode.ID, "SQL 注入漏洞")

	_, _ = data.addPOC(categoryNode.ID, &POC{
		Name: "KeyWord-SQL注入",
		Steps: []RequestStep{
			{
				Name:      "注入验证",
				Method:    "POST",
				Path:      "/service/monitorservlet",
				Body:      "key=1' OR 1=1--",
				BodyType:  "Form",
				MatchRule: "body:SQL syntax",
			},
		},
	})

	_, _ = data.addPOC(categoryNode.ID, &POC{
		Name: "Login-Bypass",
		Steps: []RequestStep{
			{
				Name:      "绕过登录",
				Method:    "GET",
				Path:      "/admin/index.jsp",
				Params:    "bypass=true",
				MatchRule: "body:Welcome Admin",
			},
		},
	})

	return data
}

func clonePOC(src *POC) *POC {
	if src == nil {
		return nil
	}

	copyValue := *src
	if len(src.Steps) > 0 {
		copyValue.Steps = append([]RequestStep(nil), src.Steps...)
	}
	copyValue.normalize()
	return &copyValue
}

func defaultRequestStep(name string) RequestStep {
	if strings.TrimSpace(name) == "" {
		name = "步骤 1"
	}
	return RequestStep{
		Name:     name,
		Method:   "GET",
		Path:     "/",
		BodyType: "Raw",
	}
}

func (step *RequestStep) normalize(index int) {
	if step == nil {
		return
	}

	if strings.TrimSpace(step.Name) == "" {
		step.Name = fmt.Sprintf("步骤 %d", index+1)
	}
	step.Method = strings.ToUpper(strings.TrimSpace(valueOr(step.Method, "GET")))
	step.Path = valueOr(step.Path, "/")
	step.BodyType = valueOr(step.BodyType, "Raw")
}

func (p *POC) normalize() {
	if p == nil {
		return
	}

	if strings.TrimSpace(p.Name) == "" {
		p.Name = "新建POC"
	}

	if len(p.Steps) == 0 {
		legacyStep := defaultRequestStep("步骤 1")
		legacyStep.Method = valueOr(strings.ToUpper(strings.TrimSpace(p.Method)), "GET")
		legacyStep.Path = valueOr(p.Path, "/")
		legacyStep.Params = p.Params
		legacyStep.Body = p.Body
		legacyStep.BodyType = valueOr(p.BodyType, "Raw")
		legacyStep.Headers = p.Headers
		legacyStep.MatchRule = p.MatchRule
		p.Steps = []RequestStep{legacyStep}
	}

	for i := range p.Steps {
		p.Steps[i].normalize(i)
	}

	firstStep := p.Steps[0]
	p.Method = firstStep.Method
	p.Path = firstStep.Path
	p.Params = firstStep.Params
	p.Body = firstStep.Body
	p.BodyType = firstStep.BodyType
	p.Headers = firstStep.Headers
	p.MatchRule = firstStep.MatchRule
}

func (p *POC) normalizedSteps() []RequestStep {
	p.normalize()
	return append([]RequestStep(nil), p.Steps...)
}

func (d *appData) ensure() {
	if d.Nodes == nil {
		d.Nodes = make(map[string]*Node)
	}
	if d.RootIDs == nil {
		d.RootIDs = []string{}
	}
}

func (d *appData) nextID() string {
	d.Counter++
	return strconv.Itoa(d.Counter)
}

func (d *appData) addGroup(parentID, name string) (*Node, error) {
	d.ensure()

	node := &Node{
		ID:       d.nextID(),
		ParentID: parentID,
		Name:     name,
		IsGroup:  true,
		Children: []string{},
	}
	d.Nodes[node.ID] = node

	if parentID == "" {
		d.RootIDs = append(d.RootIDs, node.ID)
		return node, nil
	}

	parent, ok := d.Nodes[parentID]
	if !ok {
		delete(d.Nodes, node.ID)
		return nil, fmt.Errorf("父节点不存在")
	}
	if !parent.IsGroup {
		delete(d.Nodes, node.ID)
		return nil, fmt.Errorf("不能在 POC 节点下创建子节点")
	}

	parent.Children = append(parent.Children, node.ID)
	return node, nil
}

func (d *appData) addPOC(parentID string, poc *POC) (*Node, error) {
	d.ensure()

	parent, ok := d.Nodes[parentID]
	if !ok {
		return nil, fmt.Errorf("父节点不存在")
	}
	if !parent.IsGroup {
		return nil, fmt.Errorf("请选择文件夹后再创建 POC")
	}

	if poc == nil {
		poc = &POC{
			Name:  "新建POC",
			Steps: []RequestStep{defaultRequestStep("步骤 1")},
		}
	}
	poc.normalize()

	node := &Node{
		ID:       d.nextID(),
		ParentID: parentID,
		Name:     poc.Name,
		IsGroup:  false,
		Data:     clonePOC(poc),
	}

	d.Nodes[node.ID] = node
	parent.Children = append(parent.Children, node.ID)
	return node, nil
}

func (d *appData) deleteNode(nodeID string) error {
	d.ensure()

	node, ok := d.Nodes[nodeID]
	if !ok {
		return fmt.Errorf("节点不存在")
	}

	if node.ParentID == "" {
		newRoots := make([]string, 0, len(d.RootIDs))
		for _, rootID := range d.RootIDs {
			if rootID != nodeID {
				newRoots = append(newRoots, rootID)
			}
		}
		d.RootIDs = newRoots
	} else if parent, ok := d.Nodes[node.ParentID]; ok {
		newChildren := make([]string, 0, len(parent.Children))
		for _, childID := range parent.Children {
			if childID != nodeID {
				newChildren = append(newChildren, childID)
			}
		}
		parent.Children = newChildren
	}

	d.deleteNodeRecursive(nodeID)
	return nil
}

func (d *appData) deleteNodeRecursive(nodeID string) {
	node, ok := d.Nodes[nodeID]
	if !ok {
		return
	}

	for _, childID := range append([]string(nil), node.Children...) {
		d.deleteNodeRecursive(childID)
	}

	delete(d.Nodes, nodeID)
}

func (d *appData) collectPOCs(nodeID string) []*POC {
	d.ensure()

	results := []*POC{}

	var walk func(string)
	walk = func(currentID string) {
		node, ok := d.Nodes[currentID]
		if !ok {
			return
		}
		if node.IsGroup {
			for _, childID := range node.Children {
				walk(childID)
			}
			return
		}
		if node.Data != nil {
			results = append(results, clonePOC(node.Data))
		}
	}

	walk(nodeID)
	return results
}

func (d *appData) validate() error {
	d.ensure()

	if len(d.Nodes) == 0 {
		return nil
	}

	rootSeen := make(map[string]bool, len(d.RootIDs))
	for _, rootID := range d.RootIDs {
		if rootSeen[rootID] {
			return fmt.Errorf("根节点 %s 重复", rootID)
		}
		rootSeen[rootID] = true

		node, ok := d.Nodes[rootID]
		if !ok {
			return fmt.Errorf("根节点 %s 不存在", rootID)
		}
		if node.ParentID != "" {
			return fmt.Errorf("根节点 %s 的父节点必须为空", rootID)
		}
	}

	maxCounter := 0
	for id, node := range d.Nodes {
		if node == nil {
			return fmt.Errorf("节点 %s 为空", id)
		}
		if node.ID != id {
			return fmt.Errorf("节点 %s 的内部 ID 不一致", id)
		}
		if node.Name == "" {
			return fmt.Errorf("节点 %s 名称不能为空", id)
		}
		if node.IsGroup {
			if node.Children == nil {
				node.Children = []string{}
			}
		} else if node.Data == nil {
			return fmt.Errorf("POC 节点 %s 缺少数据", id)
		} else {
			node.Data.normalize()
			if len(node.Data.Steps) == 0 {
				return fmt.Errorf("POC 节点 %s 缺少请求步骤", id)
			}
		}

		if node.ParentID == "" {
			if !rootSeen[id] {
				return fmt.Errorf("节点 %s 没有父节点且未出现在根列表中", id)
			}
		} else {
			parent, ok := d.Nodes[node.ParentID]
			if !ok {
				return fmt.Errorf("节点 %s 的父节点 %s 不存在", id, node.ParentID)
			}
			if !parent.IsGroup {
				return fmt.Errorf("节点 %s 的父节点 %s 不是文件夹", id, node.ParentID)
			}
			if !containsString(parent.Children, id) {
				return fmt.Errorf("节点 %s 未出现在父节点 %s 的 children 中", id, node.ParentID)
			}
		}

		childSeen := make(map[string]bool, len(node.Children))
		for _, childID := range node.Children {
			if childSeen[childID] {
				return fmt.Errorf("节点 %s 存在重复子节点 %s", id, childID)
			}
			childSeen[childID] = true

			child, ok := d.Nodes[childID]
			if !ok {
				return fmt.Errorf("节点 %s 的子节点 %s 不存在", id, childID)
			}
			if child.ParentID != id {
				return fmt.Errorf("节点 %s 的子节点 %s 父指针不一致", id, childID)
			}
		}

		if numericID, err := strconv.Atoi(id); err == nil && numericID > maxCounter {
			maxCounter = numericID
		}
	}

	if d.Counter < maxCounter {
		d.Counter = maxCounter
	}

	visitState := make(map[string]int, len(d.Nodes))
	var visit func(string) error
	visit = func(id string) error {
		switch visitState[id] {
		case 1:
			return fmt.Errorf("检测到循环引用，节点 %s", id)
		case 2:
			return nil
		}

		visitState[id] = 1
		node := d.Nodes[id]
		for _, childID := range node.Children {
			if err := visit(childID); err != nil {
				return err
			}
		}
		visitState[id] = 2
		return nil
	}

	for _, rootID := range d.RootIDs {
		if err := visit(rootID); err != nil {
			return err
		}
	}

	for id := range d.Nodes {
		if visitState[id] == 0 {
			return fmt.Errorf("节点 %s 未挂载到任何根节点", id)
		}
	}

	return nil
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
