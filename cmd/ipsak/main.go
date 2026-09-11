package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/linsomniac/ipsak/internal/cli"
)

var version = "1.0.0-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Execute(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version)
	stop()
	os.Exit(code)
}
