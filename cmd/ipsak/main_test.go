package main

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	for _, tt := range []struct {
		name, stamped string
		info          *debug.BuildInfo
		want          string
	}{
		{"release build", "1.2.3", &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}}, "1.2.3"},
		{"go install of a tag", "", &debug.BuildInfo{Main: debug.Module{Version: "v1.0.1"}}, "1.0.1"},
		{"go build in a checkout", "", &debug.BuildInfo{Main: debug.Module{Version: "v1.0.1-0.20261015222109-eef6a9600a6f+dirty"}}, "1.0.1-0.20261015222109-eef6a9600a6f+dirty"},
		{"build without VCS stamping", "", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "dev"},
		{"no build info", "", nil, "dev"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.stamped, tt.info); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
