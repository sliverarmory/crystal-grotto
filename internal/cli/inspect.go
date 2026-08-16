// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sliverarmory/crystal-grotto/internal/application"
	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/server"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func newCOFFParseCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "coffparse <file.o>",
		Short: "Print a COFF object as Crystal Grotto sees it",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			object, err := coff.Parse(data)
			if err != nil {
				return err
			}
			fmt.Fprint(command.OutOrStdout(), object.String())
			return nil
		},
	}
}

func newDisassembleCommand() *cobra.Command {
	var forms bool
	var options string
	command := &cobra.Command{
		Use:   "disassemble <file.o>",
		Short: "Disassemble object code from a COFF object",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			object, err := coff.Parse(data)
			if err != nil {
				return err
			}
			if options != "" {
				return fmt.Errorf("BTF disassembly options are not implemented: %s", options)
			}
			mode := x86.Mode64
			if object.IsX86() {
				mode = x86.Mode32
			} else if !object.IsX64() {
				return fmt.Errorf("disassembly is unsupported for %s", object.Architecture())
			}
			decoder, err := x86.NewCapstone(command.Context(), mode)
			if err != nil {
				return err
			}
			defer func() { _ = decoder.Close(context.Background()) }()
			for _, section := range object.Sections {
				if !section.IsExecutable() || len(section.Data) == 0 {
					continue
				}
				fmt.Fprintf(command.OutOrStdout(), "%s (%s, %d bytes)\n", section.Name, object.Architecture(), len(section.Data))
				instructions, err := decoder.Disassemble(command.Context(), section.Data, uint64(section.VirtualAddress))
				if err != nil {
					return fmt.Errorf("disassemble section %s: %w", section.Name, err)
				}
				fmt.Fprint(command.OutOrStdout(), x86.Format(instructions, forms))
			}
			return nil
		},
	}
	command.Flags().BoolVarP(&forms, "forms", "f", false, "show instruction forms")
	command.Flags().StringVarP(&options, "options", "o", "", "apply comma-separated BTF options")
	return command
}

func newServerCommand() *cobra.Command {
	var port int
	command := &cobra.Command{
		Use:   "server",
		Short: "Start the JSON-over-HTTP linker sidecar",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			sidecar, err := server.New(application.NewService(), server.Config{})
			if err != nil {
				return err
			}
			fmt.Fprintf(command.OutOrStdout(), "Link server started: http://127.0.0.1:%d/link\n", port)
			return sidecar.ListenAndServe(command.Context(), port)
		},
	}
	command.Flags().IntVarP(&port, "port", "p", 60060, "loopback TCP port")
	return command
}
