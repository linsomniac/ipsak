package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/linsomniac/ipsak/internal/cli"
)

// AIDEV-NOTE: GoReleaser stamps release builds with -X main.version. Other
// builds fall back to the module version Go records (go install of a tag,
// or VCS stamping in a checkout), then to "dev".
var version string

func main() {
	info, _ := debug.ReadBuildInfo()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Execute(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, resolveVersion(version, info))
	stop()
	os.Exit(code)
}

func resolveVersion(stamped string, info *debug.BuildInfo) string {
	if stamped != "" {
		return stamped
	}
	if info != nil && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return "dev"
}
