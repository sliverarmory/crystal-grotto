// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sliverarmory/crystal-grotto/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	streams := cli.Streams{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}
	if err := cli.Execute(ctx, os.Args[1:], streams); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
