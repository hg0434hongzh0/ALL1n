package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBuildRunTasksCreatesTargetPOCMatrix(t *testing.T) {
	t.Parallel()

	tasks := buildRunTasks([]string{"http://one", "http://two"}, []*POC{{Name: "a"}, {Name: "b"}, {Name: "c"}})
	if len(tasks) != 6 {
		t.Fatalf("got %d tasks, want 6", len(tasks))
	}
	if tasks[0].Target != "http://one" || tasks[3].Target != "http://two" {
		t.Fatalf("unexpected task ordering: %+v", tasks)
	}
}

func TestRunBatchCompletesAllTasks(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	pocs := make([]*POC, 12)
	for i := range pocs {
		pocs[i] = &POC{Name: "batch", Method: "GET", MatchRule: "body:ok"}
	}
	tasks := buildRunTasks([]string{server.URL}, pocs)

	var count int
	for result := range RunBatch(context.Background(), NewRunner(), tasks, RunSettings{Timeout: time.Second}, 4) {
		count++
		if result.Level != "VULN" {
			t.Fatalf("unexpected result: %+v", result)
		}
	}
	if count != len(tasks) {
		t.Fatalf("got %d results, want %d", count, len(tasks))
	}
}

func TestRunBatchCancellationClosesChannel(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer server.Close()

	pocs := make([]*POC, 20)
	for i := range pocs {
		pocs[i] = &POC{Name: "cancel", Method: "GET", MatchRule: "body:ok"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	results := RunBatch(ctx, NewRunner(), buildRunTasks([]string{server.URL}, pocs), RunSettings{Timeout: 2 * time.Second}, 4)
	cancel()

	done := make(chan struct{})
	go func() {
		for range results {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("batch result channel did not close after cancellation")
	}
}
