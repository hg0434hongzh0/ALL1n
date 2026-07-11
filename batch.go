package main

import (
	"context"
	"sync"
)

type RunTask struct {
	Target string
	POC    *POC
}

func buildRunTasks(targets []string, pocs []*POC) []RunTask {
	if len(targets) == 0 || len(pocs) == 0 {
		return nil
	}
	tasks := make([]RunTask, 0, len(targets)*len(pocs))
	for _, target := range targets {
		for _, poc := range pocs {
			tasks = append(tasks, RunTask{Target: target, POC: poc})
		}
	}
	return tasks
}

// RunBatch executes tasks with a bounded worker pool. The returned channel is
// always closed after all started work exits; callers should consume it until
// closed, including after cancellation.
func RunBatch(ctx context.Context, runner *Runner, tasks []RunTask, settings RunSettings, concurrency int) <-chan ExploitResult {
	results := make(chan ExploitResult, max(1, concurrency))
	if ctx == nil {
		ctx = context.Background()
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(tasks) && len(tasks) > 0 {
		concurrency = len(tasks)
	}

	go func() {
		defer close(results)
		if len(tasks) == 0 {
			return
		}

		jobs := make(chan RunTask)
		var workers sync.WaitGroup
		workers.Add(concurrency)
		for range concurrency {
			go func() {
				defer workers.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case task, ok := <-jobs:
						if !ok {
							return
						}
						results <- runner.RunContext(ctx, task.Target, task.POC, settings)
					}
				}
			}()
		}

		func() {
			defer close(jobs)
			for _, task := range tasks {
				select {
				case jobs <- task:
				case <-ctx.Done():
					return
				}
			}
		}()
		workers.Wait()
	}()

	return results
}
