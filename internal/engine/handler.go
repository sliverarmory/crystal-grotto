// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sliverarmory/crystal-grotto/internal/binutil"
	"github.com/sliverarmory/crystal-grotto/internal/coff"
	crystalhash "github.com/sliverarmory/crystal-grotto/internal/hash"
	hookmodel "github.com/sliverarmory/crystal-grotto/internal/hooks"
	"github.com/sliverarmory/crystal-grotto/internal/ised"
	"github.com/sliverarmory/crystal-grotto/internal/linker"
	"github.com/sliverarmory/crystal-grotto/internal/resolver"
	"github.com/sliverarmory/crystal-grotto/internal/rulegen"
	"github.com/sliverarmory/crystal-grotto/internal/spec"
)

var (
	_ spec.CommandHandler          = (*Handler)(nil)
	_ spec.RuleProvider            = (*Handler)(nil)
	_ spec.RuleGenerationRequester = (*Handler)(nil)
)

// Handler is the default request-local implementation of spec.CommandHandler.
// Its dependencies are immutable, and all command state lives in stack
// artifacts, so Handle is safe to call from independent executions.
type Handler struct {
	marshalCOFF     coffMarshaler
	newDisassembler disassemblerFactory
	stdout          io.Writer
	random          io.Reader
	ruleOptions     rulegen.GenerateOptions

	rulesMu       sync.Mutex
	generateRules bool
	rules         []byte
	rulesErr      error

	diagnosticsMu   sync.Mutex
	diagnosticFiles map[string]struct{}
}

// New constructs the default object/linker command handler.
func New() *Handler {
	return &Handler{
		marshalCOFF:     defaultCOFFMarshaler,
		newDisassembler: defaultDisassemblerFactory,
		stdout:          os.Stdout,
		diagnosticFiles: make(map[string]struct{}),
	}
}

// Factory has the exact signature expected by application.HandlerFactory.
func Factory() spec.CommandHandler { return New() }

// GeneratedRules returns an empty rule set unless the exported artifact asked
// for upstream rule generation. Handler instances are request-scoped (Factory
// returns a fresh one), while the mutex also makes accidental concurrent reads
// and writes data-race-free.
func (h *Handler) GeneratedRules() ([]byte, error) {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()
	h.generateRules = false
	return append([]byte(nil), h.rules...), h.rulesErr
}

// RequestRuleGeneration enables rule output for the next request-local
// execution. It mirrors the global rulegen handle created by upstream's
// runAndGenerate API.
func (h *Handler) RequestRuleGeneration() {
	h.rulesMu.Lock()
	h.generateRules = true
	h.rules = nil
	h.rulesErr = nil
	h.rulesMu.Unlock()
}

func (h *Handler) ruleGenerationRequested() bool {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()
	return h.generateRules
}

func (h *Handler) appendRuleGeneration(result rulegen.Result, err error) {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()
	if err != nil {
		h.rulesErr = err
		return
	}
	h.rules = append(h.rules, result.YARA...)
}

// Handle implements deterministic Crystal Palace object commands.
func (h *Handler) Handle(context *spec.ExecutionContext, command *spec.Command, arguments []string) (bool, error) {
	if context == nil {
		return true, errors.New("engine: execution context is nil")
	}
	if command == nil {
		return true, errors.New("engine: command is nil")
	}

	switch command.Name() {
	case "make":
		return true, h.handleMake(context, command, arguments)
	case "export":
		if err := requireArguments(command.Name(), arguments, 0, 0); err != nil {
			return true, err
		}
		artifact, value, err := popArtifact(context)
		if err != nil {
			return true, err
		}
		output, err := h.export(context, artifact)
		if err != nil {
			return true, err
		}
		context.Push(spec.StackValue{Data: output, Source: value.Source})
		return true, nil
	case "merge":
		return true, h.handleMerge(context, command, arguments)
	case "mergelib":
		return true, h.handleMergeLibrary(context, command, arguments)
	case "options":
		if err := requireArguments(command.Name(), arguments, 0, 0); err != nil {
			return true, err
		}
		return true, mutateArtifact(context, func(artifact *Artifact) error {
			artifact.addOptions(command.Options())
			return nil
		})
	case "entry":
		if err := requireArguments(command.Name(), arguments, 1, 1); err != nil {
			return true, err
		}
		return true, mutateArtifact(context, func(artifact *Artifact) error {
			artifact.config.entry = arguments[0]
			artifact.config.entrySet = true
			return nil
		})
	case "strip":
		if err := requireArguments(command.Name(), arguments, 1, 1); err != nil {
			return true, err
		}
		return true, mutateArtifact(context, func(artifact *Artifact) error {
			artifact.addStrip(binutil.SplitList(arguments[0]))
			return nil
		})
	case "remap":
		if err := requireArguments(command.Name(), arguments, 2, 2); err != nil {
			return true, err
		}
		return true, mutateArtifact(context, func(artifact *Artifact) error {
			return artifact.object.RemapSymbol(arguments[0], arguments[1])
		})
	case "patch":
		return true, h.handlePatch(context, command, arguments)
	case "link", "linkfunc":
		return true, h.handleLink(context, command, arguments)
	case "import":
		return true, h.handleImport(context, command, arguments)
	case "exportfunc":
		return true, h.handleExportFunction(context, command, arguments)
	case "magic":
		return true, h.handleMagic(context, command, arguments)
	case "coffparse", "disassemble":
		return true, h.handleDiagnostic(context, command, arguments)
	case "reladdr":
		return true, errors.New("reladdr is removed. Use fixptrs to avoid the x86 address hacks")
	case "rule":
		parsed, err := rulegen.ParseArgs(arguments)
		if err != nil {
			return true, err
		}
		_ = parsed // Parsing here preserves command-time validation.
		return true, mutateArtifact(context, func(artifact *Artifact) error {
			artifact.setRuleArguments(arguments)
			return nil
		})
	case "fixptrs":
		return true, h.handleFixPointers(context, command, arguments)
	case "fixbss":
		return true, h.handleFixBSS(context, command, arguments)
	case "attach", "redirect", "addhook", "filterhooks", "preserve", "protect", "optout", "intrinsic", "catch":
		return true, h.handleHookDirective(context, command, arguments)
	case "dfr":
		return true, h.handleResolver(context, command, arguments)
	case "ised":
		return true, h.handleISED(context, command, arguments)
	case "linkpost":
		return true, h.handleLinkPost(context, command, arguments)
	case "modcall":
		return true, &UnsupportedError{Features: []string{"modcall"}}
	default:
		return false, nil
	}
}

func (h *Handler) handleLinkPost(execution *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	if err := requireArguments(command.Name(), arguments, 2, 2); err != nil {
		return err
	}
	if arguments[1] != "unwind" {
		return fmt.Errorf("Invalid linkpost key %q", arguments[1])
	}
	return mutateArtifact(execution, func(artifact *Artifact) error {
		if artifact.kind != KindPIC && artifact.kind != KindPIC64 {
			return errors.New("linkpost is PIC-only")
		}
		artifact.addOptions([]string{"+unwind"})
		artifact.setLinkPost(arguments[0])
		return nil
	})
}

func (h *Handler) handleISED(execution *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("ised expects a verb, pattern, and byte variable")
	}
	content, err := execution.Environment().Bytes(arguments[len(arguments)-1])
	if err != nil {
		return err
	}
	directive := ised.Directive{
		Arguments: append([]string(nil), arguments...),
		Options:   command.Options(),
		Content:   content,
	}
	return mutateArtifact(execution, func(artifact *Artifact) error {
		updated, err := ised.Replay(artifact.config.ised, []ised.Directive{directive})
		if err != nil {
			return err
		}
		artifact.config.ised = updated
		return nil
	})
}

func (h *Handler) handleResolver(execution *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	directive, err := resolver.ParseDirective(arguments, command.HasOption("+clear"))
	if err != nil {
		return err
	}
	return mutateArtifact(execution, func(artifact *Artifact) error {
		updated, err := resolver.Replay(artifact.object, artifact.config.resolvers, []resolver.Directive{directive})
		if err != nil {
			return err
		}
		artifact.config.resolvers = updated
		return nil
	})
}

func (h *Handler) handleHookDirective(execution *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	directive, err := hookmodel.Parse(command.Name(), arguments)
	if err != nil {
		return err
	}
	return mutateArtifact(execution, func(artifact *Artifact) error {
		if artifact.config.hooks == nil {
			model, err := hookmodel.New(artifact.object)
			if err != nil {
				return err
			}
			artifact.config.hooks = model
		}
		updated, err := artifact.config.hooks.Apply(context.Background(), artifact.object, directive,
			hookmodel.ByteResolver(func(reference string) ([]byte, error) {
				return execution.Environment().Bytes(reference)
			}),
		)
		if err != nil {
			return err
		}
		artifact.config.hooks = updated
		return nil
	})
}

func (h *Handler) handleMake(context *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	if err := requireArguments(command.Name(), arguments, 1, 1); err != nil {
		return err
	}
	kind := Kind(arguments[0])
	switch kind {
	case KindCOFF, KindObject, KindPIC, KindPIC64:
	default:
		return fmt.Errorf("make type %q is invalid; use coff, object, pic, or pic64", arguments[0])
	}
	if kind == KindPIC64 && context.Arch() != "x64" {
		return errors.New("make pic64 is x64-only")
	}

	value, err := popBytes(context)
	if err != nil {
		return err
	}
	object, err := coff.Parse(value.Data)
	if err != nil {
		return err
	}
	if object.Architecture() != context.Arch() {
		return fmt.Errorf("%s COFF arch differs from %s .spec target", object.Architecture(), context.Target())
	}
	if command.HasOption("+relax") {
		if _, err := coff.RelaxReferencePointers(object); err != nil {
			return err
		}
	}
	artifact := newArtifact(kind, object)
	artifact.addOptions(command.Options())
	context.Push(spec.StackValue{Object: artifact, Source: value.Source})
	return nil
}

func (h *Handler) handleMerge(context *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	if err := requireArguments(command.Name(), arguments, 0, 0); err != nil {
		return err
	}
	argument, err := popBytes(context)
	if err != nil {
		return err
	}
	additional, err := coff.Parse(argument.Data)
	if err != nil {
		return err
	}
	if additional.Architecture() != context.Arch() {
		return fmt.Errorf("%s COFF arch differs from %s .spec target", additional.Architecture(), context.Target())
	}
	artifact, value, err := popArtifact(context)
	if err != nil {
		return err
	}
	if artifact.hasOption("+relax") {
		if _, err := coff.RelaxReferencePointers(additional); err != nil {
			return err
		}
	}
	merged, err := linker.Merge(artifact.object, additional)
	if err != nil {
		return err
	}
	artifact.object = merged
	context.Push(spec.StackValue{Object: artifact, Source: value.Source})
	return nil
}

func (h *Handler) handlePatch(context *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	if err := requireArguments(command.Name(), arguments, 2, 2); err != nil {
		return err
	}
	data, err := context.Environment().Bytes(arguments[1])
	if err != nil {
		return err
	}
	return mutateArtifact(context, func(artifact *Artifact) error {
		if context.Arch() == "x86" && (artifact.kind == KindPIC || artifact.kind == KindPIC64) && artifact.config.returnAddress == "" {
			return errors.New("x86 PIC requires fixptrs is set to use patch")
		}
		if err := validatePatch(artifact.object, arguments[0], data); err != nil {
			return err
		}
		artifact.setPatch(arguments[0], data)
		return nil
	})
}

func (h *Handler) handleFixPointers(context *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	if err := requireArguments(command.Name(), arguments, 1, 1); err != nil {
		return err
	}
	return mutateArtifact(context, func(artifact *Artifact) error {
		if context.Arch() != "x86" || artifact.kind != KindPIC {
			return errors.New("fixptrs [_symbol] is x86 PIC-only")
		}
		if _, err := requireFunction(artifact.object, arguments[0]); err != nil {
			return err
		}
		artifact.config.returnAddress = arguments[0]
		return nil
	})
}

func (h *Handler) handleFixBSS(context *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	if err := requireArguments(command.Name(), arguments, 1, 1); err != nil {
		return err
	}
	return mutateArtifact(context, func(artifact *Artifact) error {
		if artifact.kind != KindPIC && artifact.kind != KindPIC64 {
			return errors.New("fixbss [symbol] is PIC-only")
		}
		if _, err := requireFunction(artifact.object, arguments[0]); err != nil {
			return err
		}
		artifact.config.getBSS = arguments[0]
		return nil
	})
}

func (h *Handler) handleLink(context *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	if err := requireArguments(command.Name(), arguments, 1, 1); err != nil {
		return err
	}
	linked, err := popBytes(context)
	if err != nil {
		return err
	}
	artifact, value, err := popArtifact(context)
	if err != nil {
		return err
	}
	if arguments[0] == "" {
		return errors.New("linked section name is empty")
	}
	executable := command.Name() == "linkfunc"
	if executable {
		symbol, err := requireFunction(artifact.object, arguments[0])
		if err != nil {
			return err
		}
		if symbol.Section != nil {
			return fmt.Errorf("Symbol %s is already defined.", arguments[0])
		}
	}
	artifact.setLink(linker.LinkedSection{Name: arguments[0], Data: linked.Data, Executable: executable})
	context.Push(spec.StackValue{Object: artifact, Source: value.Source})
	return nil
}

func (h *Handler) handleImport(context *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	if err := requireArguments(command.Name(), arguments, 1, 1); err != nil {
		return err
	}
	return mutateArtifact(context, func(artifact *Artifact) error {
		if artifact.kind != KindObject {
			return errors.New("Argument is not a PICO (COFF) - can't import functions to it")
		}
		apis, err := resolver.ParseAPITable(arguments[0])
		if err != nil {
			return err
		}
		artifact.config.apis = append([]string(nil), apis...)
		return nil
	})
}

func (h *Handler) handleExportFunction(context *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	if err := requireArguments(command.Name(), arguments, 2, 2); err != nil {
		return err
	}
	return mutateArtifact(context, func(artifact *Artifact) error {
		if artifact.kind != KindObject {
			return errors.New("exportfunc is for PICOs only")
		}
		if _, err := requireFunction(artifact.object, arguments[0]); err != nil {
			return err
		}
		tag := (crystalhash.ROR13{}).Sum32([]byte(arguments[1]))
		if tag <= linker.PICOReservedExportMax {
			return fmt.Errorf("Choose a different tag %s for %s. Tag hashes to a reserved value (%08x).", arguments[1], arguments[0], tag)
		}
		return artifact.setExport(linker.Export{Symbol: arguments[0], Tag: tag})
	})
}

func (h *Handler) handleMagic(context *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	if err := requireArguments(command.Name(), arguments, 1, 1); err != nil {
		return err
	}
	values := binutil.SplitList(arguments[0])
	magic := make([]uint32, 0, len(values))
	for _, value := range values {
		number, err := binutil.DecodeNumber(value, 32)
		if err != nil {
			return err
		}
		low, err := binutil.LowBits(number, 32)
		if err != nil {
			return err
		}
		magic = append(magic, uint32(low))
	}
	return mutateArtifact(context, func(artifact *Artifact) error {
		artifact.config.magic = append([]uint32(nil), magic...)
		return nil
	})
}

func (h *Handler) handleDiagnostic(context *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	if err := requireArguments(command.Name(), arguments, 1, 2); err != nil {
		return err
	}
	output, err := diagnosticOutput(arguments[0])
	if err != nil {
		return err
	}
	if len(arguments) == 2 {
		output.Title = arguments[1]
	}
	output.ShowForms = command.HasOption("+forms")
	return mutateArtifact(context, func(artifact *Artifact) error {
		if command.Name() == "coffparse" {
			if artifact.config.coffParse != nil {
				return errors.New("coffparse is already defined")
			}
			artifact.config.coffParse = output
		} else {
			if artifact.config.disassemble != nil {
				return errors.New("disassemble is already defined")
			}
			artifact.config.disassemble = output
		}
		return nil
	})
}

func (h *Handler) validateDeferred(context *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	switch command.Name() {
	case "fixptrs":
		if context.Arch() != "x86" {
			return errors.New("fixptrs [_symbol] is x86 PIC-only")
		}
	case "catch":
		if context.Arch() != "x64" {
			return errors.New("catch is x64-only")
		}
	case "intrinsic":
		if len(arguments) == 2 {
			prefix := "__"
			if context.Arch() == "x86" {
				prefix = "___"
			}
			if !strings.HasPrefix(arguments[0], prefix) {
				return fmt.Errorf("Intrinsic symbol %s must start with %s", arguments[0], prefix)
			}
			if _, err := context.Environment().Bytes(arguments[1]); err != nil {
				return err
			}
		}
	case "filterhooks":
		if len(arguments) == 1 {
			if _, err := context.Environment().Bytes(arguments[0]); err != nil {
				return err
			}
		}
	}
	return nil
}

func mutateArtifact(context *spec.ExecutionContext, mutate func(*Artifact) error) error {
	artifact, value, err := popArtifact(context)
	if err != nil {
		return err
	}
	if err := mutate(artifact); err != nil {
		return err
	}
	context.Push(spec.StackValue{Object: artifact, Source: value.Source})
	return nil
}

func deferArtifactCommand(context *spec.ExecutionContext, command *spec.Command, arguments []string, affectsProgram bool) error {
	return mutateArtifact(context, func(artifact *Artifact) error {
		artifact.deferCommand(DeferredCommand{
			Name:           command.Name(),
			Arguments:      arguments,
			Options:        command.Options(),
			AffectsProgram: affectsProgram,
		})
		return nil
	})
}

func popArtifact(context *spec.ExecutionContext) (*Artifact, spec.StackValue, error) {
	value, err := pop(context)
	if err != nil {
		return nil, spec.StackValue{}, err
	}
	if value.Object == nil {
		return nil, spec.StackValue{}, errors.New("POP expected OBJECT, received bytes")
	}
	artifact, ok := value.Object.(*Artifact)
	if !ok || artifact == nil {
		return nil, spec.StackValue{}, fmt.Errorf("POP expected Crystal Grotto object, received %s", value.Type())
	}
	if artifact.object == nil {
		return nil, spec.StackValue{}, errors.New("Crystal Grotto object has no COFF model")
	}
	return artifact, value, nil
}

func popBytes(context *spec.ExecutionContext) (spec.StackValue, error) {
	value, err := pop(context)
	if err != nil {
		return spec.StackValue{}, err
	}
	if value.Object != nil {
		return spec.StackValue{}, fmt.Errorf("POP expected BYTES, received %s", value.Type())
	}
	return value, nil
}

func pop(context *spec.ExecutionContext) (spec.StackValue, error) {
	value, err := context.Pop()
	if err == nil {
		return value, nil
	}
	return spec.StackValue{}, simplifyProgramError(err)
}

func simplifyProgramError(err error) error {
	var programError *spec.ProgramError
	if errors.As(err, &programError) {
		return errors.New(programError.Message)
	}
	return err
}

func requireArguments(name string, arguments []string, minimum, maximum int) error {
	if len(arguments) >= minimum && len(arguments) <= maximum {
		return nil
	}
	if minimum == maximum {
		return fmt.Errorf("%s expects %d argument(s), got %d", name, minimum, len(arguments))
	}
	return fmt.Errorf("%s expects %d..%d arguments, got %d", name, minimum, maximum, len(arguments))
}

func requireFunction(object *coff.Object, name string) (*coff.Symbol, error) {
	symbol := object.GetSymbol(name)
	if symbol == nil && object.Machine == coff.MachineI386 {
		for _, candidate := range object.Symbols {
			if strings.HasPrefix(candidate.Name, name+"@") || strings.HasPrefix(candidate.Name, "_"+name+"@") {
				return nil, fmt.Errorf("Symbol %s does not exist. Did you mean %s?", name, candidate.Name)
			}
		}
		if candidate := object.GetSymbol("_" + name); candidate != nil {
			return nil, fmt.Errorf("Symbol %s does not exist. Did you mean _%s?", name, name)
		}
	}
	if symbol == nil {
		return nil, fmt.Errorf("Symbol %s does not exist.", name)
	}
	if !symbol.IsFunction() {
		return nil, fmt.Errorf("Symbol %s is not a function.", name)
	}
	return symbol, nil
}

func validatePatch(object *coff.Object, name string, data []byte) error {
	symbol := object.GetSymbol(name)
	if symbol == nil {
		return fmt.Errorf("No symbol %q", name)
	}
	if symbol.Section == nil {
		return fmt.Errorf("Can't patch undefined symbol %s", name)
	}
	if symbol.Section.IsUninitialized() {
		return fmt.Errorf("Can't patch symbol %s in uninitialized %s section", name, symbol.Section.Name)
	}
	estimated := symbol.EstimateSize()
	if estimated == 4 || estimated == 8 {
		if uint32(len(data)) != estimated {
			return fmt.Errorf("Symbol %s (est.) size %db differs from patch %db size", name, estimated, len(data))
		}
	} else if uint64(len(data)) > uint64(estimated) {
		return fmt.Errorf("Symbol %s (est.) size %db is LESS than patch %db size", name, estimated, len(data))
	}
	return nil
}

func diagnosticOutput(path string) (*DiagnosticOutput, error) {
	if path == "STDOUT" {
		return &DiagnosticOutput{Stdout: true}, nil
	}
	canonical, err := canonicalOutputPath(path)
	if err != nil {
		return nil, fmt.Errorf("resolve output path %q: %w", path, err)
	}
	if info, statErr := os.Stat(canonical); statErr == nil {
		if info.IsDir() {
			return nil, fmt.Errorf("Out file is a folder %s", canonical)
		}
		if info.Mode().Perm()&0o222 == 0 {
			return nil, fmt.Errorf("Out file is not writable %s", canonical)
		}
	} else if !os.IsNotExist(statErr) {
		return nil, fmt.Errorf("inspect output file %s: %w", canonical, statErr)
	}
	parent, err := os.Stat(filepath.Dir(canonical))
	if err != nil {
		return nil, fmt.Errorf("inspect output directory for %s: %w", canonical, err)
	}
	if !parent.IsDir() {
		return nil, fmt.Errorf("output parent is not a folder %s", filepath.Dir(canonical))
	}
	return &DiagnosticOutput{Path: canonical}, nil
}

func canonicalOutputPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	canonical, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return filepath.Clean(canonical), nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}
