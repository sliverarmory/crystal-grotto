// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

// Package cli implements the Crystal Grotto Cobra command tree.
package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	grotto "github.com/sliverarmory/crystal-grotto"
)

// Streams contains the process streams used by a command tree. Explicit
// streams keep CLI and sidecar tests independent of global process state.
type Streams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

// NewRootCommand constructs a fresh Cobra command tree.
func NewRootCommand(streams Streams) *cobra.Command {
	command := &cobra.Command{
		Use:           "crystal-grotto",
		Short:         "Build and transform position-independent Windows programs",
		Version:       grotto.Version,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			fmt.Fprintf(command.OutOrStdout(), "Crystal Grotto %s (Crystal Palace compatibility %s)\n\n", grotto.Version, grotto.UpstreamVersion)
			return command.Help()
		},
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	command.SetIn(streams.In)
	command.SetOut(streams.Out)
	command.SetErr(streams.Err)
	command.AddCommand(
		newBuildCommand(false),
		newLinkCommand(false),
		newCOFFParseCommand(),
		newDisassembleCommand(),
		newServerCommand(),
		newBuildCommand(true),
		newLinkCommand(true),
	)
	return command
}

// Execute constructs and executes a command tree with the supplied arguments.
func Execute(ctx context.Context, args []string, streams Streams) error {
	command := NewRootCommand(streams)
	command.SetArgs(args)
	return command.ExecuteContext(ctx)
}
