// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	grotto "github.com/sliverarmory/crystal-grotto"
	"github.com/sliverarmory/crystal-grotto/internal/binutil"
)

type invocation struct {
	SpecFile  string
	Target    string
	Output    string
	Generate  string
	Arguments []string
}

func newBuildCommand(compatibilityAlias bool) *cobra.Command {
	use := "build <build.spec> [label.]<x86|x64> <out.bin> [arguments...]"
	short := "Build a program"
	if compatibilityAlias {
		use = "buildPic <build.spec> [label.]<x86|x64> <out.bin> [arguments...]"
		short = "Legacy build command"
	}
	command := &cobra.Command{
		Use:                use,
		Short:              short,
		Hidden:             compatibilityAlias,
		DisableFlagParsing: true,
		Args:               cobra.ArbitraryArgs,
		RunE: func(command *cobra.Command, args []string) error {
			if wantsHelp(args) {
				return command.Help()
			}
			parsed, err := parseInvocation(args)
			if err != nil {
				return err
			}
			capability, err := grotto.None(parsed.Target)
			if err != nil {
				return err
			}
			return executeInvocation(command, parsed, capability)
		},
	}
	command.SetHelpFunc(rawCommandHelp)
	return command
}

func newLinkCommand(compatibilityAlias bool) *cobra.Command {
	use := "link <loader.spec> <file.dll|file.o> <out.bin> [arguments...]"
	short := "Link a DLL or COFF object to a loader program"
	if compatibilityAlias {
		use = "run <loader.spec> <file.dll|file.o> <out.bin> [arguments...]"
		short = "Legacy link command"
	}
	command := &cobra.Command{
		Use:                use,
		Short:              short,
		Hidden:             compatibilityAlias,
		DisableFlagParsing: true,
		Args:               cobra.ArbitraryArgs,
		RunE: func(command *cobra.Command, args []string) error {
			if wantsHelp(args) {
				return command.Help()
			}
			parsed, err := parseInvocation(args)
			if err != nil {
				return err
			}
			input, err := os.ReadFile(parsed.Target)
			if err != nil {
				return fmt.Errorf("read input capability: %w", err)
			}
			capability, err := grotto.ParseCapability(input)
			if err != nil {
				return err
			}
			return executeInvocation(command, parsed, capability)
		},
	}
	command.SetHelpFunc(rawCommandHelp)
	return command
}

func rawCommandHelp(command *cobra.Command, _ []string) {
	fmt.Fprintf(command.OutOrStdout(), "Usage:\n  crystal-grotto %s\n\n%s\n\nArguments:\n  @config.spec       Run a specification to configure variables.\n  -r %%key=value      Resolve comma-separated paths relative to the current directory.\n  -g out.yar         Write generated YARA rules.\n  A=04030201         Set byte variable $A (the $ prefix is optional).\n  %%key=value         Set a string variable.\n", command.Use, command.Short)
}

func wantsHelp(args []string) bool {
	return len(args) == 1 && (args[0] == "-h" || args[0] == "--help")
}

func parseInvocation(args []string) (invocation, error) {
	if len(args) < 3 {
		return invocation{}, fmt.Errorf("expected specification, target, and output arguments")
	}
	result := invocation{SpecFile: args[0], Target: args[1], Output: args[2]}
	for index := 3; index < len(args); index++ {
		if args[index] != "-g" {
			result.Arguments = append(result.Arguments, args[index])
			continue
		}
		if index+1 >= len(args) {
			return invocation{}, fmt.Errorf("-g is missing an output filename")
		}
		result.Generate = args[index+1]
		index++
	}
	return result, nil
}

func executeInvocation(command *cobra.Command, parsed invocation, capability grotto.Capability) error {
	environment := make(grotto.Environment)
	logger := grotto.LoggerFunc(func(message grotto.Message) {
		fmt.Fprintln(command.OutOrStdout(), message.String())
	})
	options := grotto.RunOptions{Environment: environment, Logger: logger, Handler: grotto.NewCommandHandler()}
	if err := processArguments(parsed.Arguments, capability, options); err != nil {
		return err
	}
	program, err := grotto.ParseFile(parsed.SpecFile)
	if err != nil {
		return err
	}
	if parsed.Generate != "" {
		result, err := program.RunAndGenerate(capability, options)
		if err != nil {
			return err
		}
		if err := writeOutput(parsed.Output, result.Program); err != nil {
			return err
		}
		return writeOutput(parsed.Generate, result.Rules)
	}
	result, err := program.Run(capability, options)
	if err != nil {
		return err
	}
	return writeOutput(parsed.Output, result)
}

func processArguments(arguments []string, capability grotto.Capability, options grotto.RunOptions) error {
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch {
		case argument == "-r":
			if index+1 >= len(arguments) {
				return fmt.Errorf("-r is missing %%key=value argument")
			}
			index++
			if err := processResolvedVariable(options.Environment, arguments[index]); err != nil {
				return err
			}
		case strings.HasPrefix(argument, "-r%"):
			if err := processResolvedVariable(options.Environment, strings.TrimPrefix(argument, "-r")); err != nil {
				return err
			}
		case strings.HasPrefix(argument, "-r"):
			return fmt.Errorf("-r must be followed by %%key=value")
		case strings.HasPrefix(argument, "%"):
			key, value, err := binutil.ParseKeyValue(argument)
			if err != nil {
				return err
			}
			options.Environment[key] = value
		case strings.HasPrefix(argument, "@"):
			path, err := expandHome(strings.TrimPrefix(argument, "@"))
			if err != nil {
				return err
			}
			config, err := grotto.ParseFile(path)
			if err != nil {
				return err
			}
			if _, err := config.RunConfig(capability, options); err != nil {
				return err
			}
		case strings.HasPrefix(argument, "="):
			return fmt.Errorf("Key is empty in %s - try escaping $", argument)
		default:
			key, value, err := binutil.ParseKeyValue(argument)
			if err != nil {
				return err
			}
			if !strings.HasPrefix(key, "$") {
				key = "$" + key
			}
			data, err := binutil.HexToBytes(value)
			if err != nil {
				return fmt.Errorf("Could not convert %s to byte[]: %w", key, err)
			}
			options.Environment[key] = data
		}
	}
	return nil
}

func processResolvedVariable(environment grotto.Environment, argument string) error {
	key, value, err := binutil.ParseKeyValue(argument)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(key, "%") {
		return fmt.Errorf("-r must be followed by %%key=value")
	}
	values := binutil.SplitList(value)
	for index, path := range values {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		values[index] = absolute
	}
	environment[key] = strings.Join(values, ", ")
	return nil
}

func expandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
}

func writeOutput(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
