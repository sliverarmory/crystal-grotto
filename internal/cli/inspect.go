// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

package cli

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"unicode"

	"github.com/spf13/cobra"

	grotto "github.com/sliverarmory/crystal-grotto"
	"github.com/sliverarmory/crystal-grotto/internal/application"
	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/ised"
	"github.com/sliverarmory/crystal-grotto/internal/server"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func newCOFFParseCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "coffparse <file.o>",
		Short: "Print a COFF object as Crystal Grotto sees it",
		// Crystal Palace reads args[0] and ignores later arguments.
		Args: cobra.MinimumNArgs(1),
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
			input, err := coff.Parse(data)
			if err != nil {
				return err
			}
			parsedOptions, err := parseDisassemblyOptions(options)
			if err != nil {
				return err
			}
			// Upstream always routes disassembly through `make coff`, even when
			// -o is empty. Besides applying requested transforms, that normalizes
			// subsection groups such as .text$A/.text$B before inspection.
			object, err := transformForDisassembly(command.Context(), data, input.Architecture(), parsedOptions)
			if err != nil {
				return err
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
			var textForms map[uint32]string
			textSection := object.GetSection(".text")
			if forms && textCanBeLifted(textSection, object) {
				textForms, err = provenTextForms(command.Context(), object, decoder)
				if err != nil {
					return fmt.Errorf("derive .text instruction forms: %w", err)
				}
			}
			for _, section := range object.Sections {
				if !section.IsExecutable() || len(section.Data) == 0 {
					continue
				}
				fmt.Fprintf(command.OutOrStdout(), "%s (%s, %d bytes)\n", section.Name, object.Architecture(), len(section.Data))
				instructions, err := decoder.Disassemble(command.Context(), section.Data, uint64(section.VirtualAddress))
				if err != nil {
					return fmt.Errorf("disassemble section %s: %w", section.Name, err)
				}
				if forms && section == textSection {
					applyProvenForms(instructions, uint64(section.VirtualAddress), textForms)
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

// textCanBeLifted identifies the minimum symbol boundary LiftObject needs to
// interpret .text. Symbol-free objects remain valid disassembly inputs; -f
// simply has no trustworthy function-scoped forms to add to them.
func textCanBeLifted(text *coff.Section, object *coff.Object) bool {
	if text == nil || object == nil || !text.IsExecutable() || len(text.Data) == 0 {
		return false
	}
	for _, symbol := range object.Symbols {
		if symbol != nil && symbol.Section == text && symbol.Value == 0 && (symbol.IsFunction() || symbol.IsGlobalVariable()) {
			return true
		}
	}
	return false
}

// provenTextForms reuses the caller-owned decoder. LiftObject therefore does
// not start or close a second decoder, and its conservative semantic subset is
// the sole source of canonical form strings.
func provenTextForms(ctx context.Context, object *coff.Object, decoder x86.Disassembler) (map[uint32]string, error) {
	program, err := ised.LiftObject(ctx, object, ised.ObjectOptions{Disassembler: decoder})
	if err != nil {
		return nil, err
	}
	forms := make(map[uint32]string)
	for _, function := range program.Functions {
		if function.Section != ".text" {
			continue
		}
		for _, instruction := range function.Instructions {
			if instruction.Form != "" {
				forms[instruction.Offset] = instruction.Form
			}
		}
	}
	return forms, nil
}

func applyProvenForms(instructions []x86.Instruction, base uint64, forms map[uint32]string) {
	for index := range instructions {
		if instructions[index].Address < base {
			continue
		}
		offset := instructions[index].Address - base
		if offset > math.MaxUint32 {
			continue
		}
		instructions[index].Form = forms[uint32(offset)]
	}
}

var disassemblyBTFOptions = map[string]struct{}{
	"+optimize":   {},
	"+disco":      {},
	"+mutate":     {},
	"+gofirst":    {},
	"+blockparty": {},
	"+shatter":    {},
	"+regdance":   {},
	"+relax":      {},
	"+unwind":     {},
}

// parseDisassemblyOptions mirrors CrystalUtils.toSet()'s comma-separated,
// insertion-ordered de-duplication while also accepting whitespace between
// option tokens. Keeping this whitelist at the CLI boundary prevents an
// option string from becoming injected specification source.
func parseDisassemblyOptions(value string) ([]string, error) {
	fields := strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || unicode.IsSpace(character)
	})
	result := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, option := range fields {
		if _, supported := disassemblyBTFOptions[option]; !supported {
			return nil, fmt.Errorf("invalid BTF disassembly option %q", option)
		}
		if _, duplicate := seen[option]; duplicate {
			continue
		}
		seen[option] = struct{}{}
		result = append(result, option)
	}
	if _, shatter := seen["+shatter"]; shatter {
		if _, unwind := seen["+unwind"]; unwind {
			return nil, errors.New("Options +shatter and +unwind are not compatible")
		}
	}
	return result, nil
}

func transformForDisassembly(ctx context.Context, data []byte, architecture string, options []string) (*coff.Object, error) {
	if ctx == nil {
		return nil, errors.New("disassemble: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if architecture != "x86" && architecture != "x64" {
		return nil, fmt.Errorf("disassembly is unsupported for %s", architecture)
	}
	capability, err := grotto.ParseObject(data)
	if err != nil {
		return nil, err
	}
	content := architecture + ".o:\n" +
		"  push $OBJECT\n" +
		"  make coff " + strings.Join(options, " ") + "\n" +
		"  export\n"
	program, err := grotto.Parse("disassemble.spec", content)
	if err != nil {
		return nil, err
	}
	transformed, err := program.Run(capability, grotto.RunOptions{})
	if err != nil {
		return nil, fmt.Errorf("apply BTF disassembly options %s: %w", strings.Join(options, ","), err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	object, err := coff.Parse(transformed)
	if err != nil {
		return nil, fmt.Errorf("parse transformed COFF: %w", err)
	}
	return object, nil
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
