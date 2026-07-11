package main

import "testing"

func TestSelectedProductNodeCollectsAllNestedPOCsForOneTarget(t *testing.T) {
	t.Parallel()

	data := newAppData()
	product, _ := data.addGroup("", "U8Cloud")
	sql, _ := data.addGroup(product.ID, "SQL 注入")
	file, _ := data.addGroup(product.ID, "文件漏洞")
	_, _ = data.addPOC(sql.ID, &POC{Name: "SQL-1", Method: "GET", MatchRule: "ok"})
	_, _ = data.addPOC(sql.ID, &POC{Name: "SQL-2", Method: "GET", MatchRule: "ok"})
	_, _ = data.addPOC(file.ID, &POC{Name: "File-1", Method: "GET", MatchRule: "ok"})

	pocs := data.collectPOCs(product.ID)
	if len(pocs) != 3 {
		t.Fatalf("selected product collected %d POCs, want 3", len(pocs))
	}
	tasks := buildRunTasks([]string{"https://u8.example.com"}, pocs)
	if len(tasks) != 3 {
		t.Fatalf("one target produced %d tasks, want 3", len(tasks))
	}
	for _, task := range tasks {
		if task.Target != "https://u8.example.com" {
			t.Fatalf("unexpected task target: %s", task.Target)
		}
	}
}
