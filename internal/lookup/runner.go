// Package lookup runs independent network lookups concurrently and retains partial results.
package lookup

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type Section struct {
	Key        string `json:"key"`
	Title      string `json:"title"`
	Source     string `json:"source,omitempty"`
	Status     string `json:"status"`
	Data       any    `json:"data,omitempty"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

type Report struct {
	SchemaVersion int       `json:"schema_version"`
	Command       string    `json:"command"`
	Target        string    `json:"target,omitempty"`
	Sections      []Section `json:"sections"`
}

type Task struct {
	Key, Title, Source string
	Depends            []string
	Run                func(context.Context, map[string]Section) (any, error)
}

type Skip string

func (s Skip) Error() string { return string(s) }

// Run validates the graph before starting work. The channel has room for every
// result, so a slow UI cannot delay providers or cancellation. Results are final
// immutable values; callers aggregate them in their original task order.
func Run(ctx context.Context, tasks []Task) (<-chan Section, error) {
	indices := make(map[string]int, len(tasks))
	for i, t := range tasks {
		if t.Key == "" || t.Run == nil {
			return nil, fmt.Errorf("invalid lookup task %q", t.Key)
		}
		if _, exists := indices[t.Key]; exists {
			return nil, fmt.Errorf("duplicate lookup %s", t.Key)
		}
		indices[t.Key] = i
	}
	seen := make([]int, len(tasks))
	var visit func(int) error
	visit = func(i int) error {
		if seen[i] == 1 {
			return fmt.Errorf("lookup dependency cycle at %s", tasks[i].Key)
		}
		if seen[i] == 2 {
			return nil
		}
		seen[i] = 1
		for _, key := range tasks[i].Depends {
			j, ok := indices[key]
			if !ok {
				return fmt.Errorf("unknown dependency %s", key)
			}
			if err := visit(j); err != nil {
				return err
			}
		}
		seen[i] = 2
		return nil
	}
	for i := range tasks {
		if err := visit(i); err != nil {
			return nil, err
		}
	}
	results := make([]Section, len(tasks))
	done := make([]chan struct{}, len(tasks))
	for i := range done {
		done[i] = make(chan struct{})
	}
	out := make(chan Section, len(tasks))
	for i, task := range tasks {
		go func(i int, t Task) {
			start := time.Now()
			s := Section{Key: t.Key, Title: t.Title, Source: t.Source, Status: "ok"}
			deps := make(map[string]Section)
			var err error
			for _, key := range t.Depends {
				select {
				case <-ctx.Done():
					err = ctx.Err()
				case <-done[indices[key]]:
					dep := results[indices[key]]
					deps[key] = dep
					if dep.Status != "ok" {
						err = Skip("requires " + key + ": " + dep.Error)
					}
				}
				if err != nil {
					break
				}
			}
			if err == nil {
				err = ctx.Err()
			}
			if err == nil {
				s.Data, err = t.Run(ctx, deps)
			}
			if err != nil {
				s.Status = "error"
				var skip Skip
				if errors.As(err, &skip) {
					s.Status = "skipped"
				}
				s.Error = err.Error()
			}
			s.DurationMS = time.Since(start).Milliseconds()
			results[i] = s
			close(done[i])
			out <- s
		}(i, task)
	}
	// Forward exactly len(tasks) results, then close, without coupling workers to consumers.
	closed := make(chan Section, len(tasks))
	go func() {
		defer close(closed)
		for range tasks {
			closed <- <-out
		}
	}()
	return closed, nil
}

func NewReport(command, target string, tasks []Task) Report {
	r := Report{SchemaVersion: 1, Command: command, Target: target, Sections: make([]Section, len(tasks))}
	for i, t := range tasks {
		r.Sections[i] = Section{Key: t.Key, Title: t.Title, Source: t.Source, Status: "pending"}
	}
	return r
}
func (r *Report) Apply(s Section) {
	for i := range r.Sections {
		if r.Sections[i].Key == s.Key {
			r.Sections[i] = s
			return
		}
	}
}
