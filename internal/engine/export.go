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

	"github.com/sliverarmory/crystal-grotto/internal/btf"
	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/coffwrite"
	"github.com/sliverarmory/crystal-grotto/internal/linker"
	"github.com/sliverarmory/crystal-grotto/internal/rulegen"
	"github.com/sliverarmory/crystal-grotto/internal/spec"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

type coffMarshaler func(*coff.Object) ([]byte, error)
type disassemblerFactory func(context.Context, coff.Machine) (x86.Disassembler, error)

func defaultCOFFMarshaler(object *coff.Object) ([]byte, error) {
	return coffwrite.Marshal(object)
}

func defaultDisassemblerFactory(ctx context.Context, machine coff.Machine) (x86.Disassembler, error) {
	mode := x86.Mode64
	if machine == coff.MachineI386 {
		mode = x86.Mode32
	} else if machine != coff.MachineAMD64 {
		return nil, fmt.Errorf("disassemble does not support %s COFF", machine)
	}
	return x86.NewCapstone(ctx, mode)
}

func (h *Handler) export(execution *spec.ExecutionContext, artifact *Artifact) ([]byte, error) {
	if artifact == nil || artifact.object == nil {
		return nil, errors.New("engine: cannot export a nil object")
	}
	if err := artifact.unsupportedError(); err != nil {
		return nil, err
	}
	normalized, err := linker.Merge(artifact.object)
	if err != nil {
		return nil, err
	}
	if _, err := btf.ApplyEasyPICFixes(context.Background(), normalized, btf.EasyPICOptions{
		GetBSS:        artifact.config.getBSS,
		ReturnAddress: artifact.config.returnAddress,
	}); err != nil {
		return nil, err
	}
	if err := h.applyOrderTransforms(artifact, normalized); err != nil {
		return nil, err
	}
	if err := h.writeDiagnostics(artifact, normalized); err != nil {
		return nil, err
	}
	if err := applyPatches(normalized, artifact.config.patches); err != nil {
		return nil, err
	}
	if err := h.generateRulesFor(execution, artifact, normalized); err != nil {
		return nil, err
	}

	switch artifact.kind {
	case KindPIC, KindPIC64:
		image, err := linker.EmitPIC(normalized, linker.PICOptions{
			EntrySymbol: entrySymbol(artifact),
			Links:       cloneLinks(artifact.config.links),
		})
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), image.Bytes...), nil
	case KindObject:
		image, err := linker.EmitPICO(normalized, linker.PICOOptions{
			EntrySymbol: entrySymbol(artifact),
			Links:       cloneLinks(artifact.config.links),
			APIs:        append([]string(nil), artifact.config.apis...),
			Exports:     append([]linker.Export(nil), artifact.config.exports...),
		})
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), image.Bytes...), nil
	case KindCOFF:
		outputObject, err := mergeCOFFLinks(normalized, artifact.config.links)
		if err != nil {
			return nil, err
		}
		if err := applyStrip(outputObject, artifact.config.strip); err != nil {
			return nil, err
		}
		marshal := h.marshalCOFF
		if marshal == nil {
			marshal = defaultCOFFMarshaler
		}
		return marshal(outputObject)
	default:
		return nil, fmt.Errorf("engine: unknown artifact type %q", artifact.kind)
	}
}

func (h *Handler) generateRulesFor(execution *spec.ExecutionContext, artifact *Artifact, object *coff.Object) error {
	if !h.ruleGenerationRequested() {
		return nil
	}
	if execution == nil {
		return errors.New("engine: cannot generate rules without an execution context")
	}
	arguments, err := rulegen.ParseArgs(artifact.config.ruleArguments)
	if err != nil {
		h.appendRuleGeneration(rulegen.Result{}, err)
		return err
	}
	options := h.ruleOptions
	if options.Random == nil {
		options.Random = h.random
	}
	result, err := rulegen.Generate(context.Background(), object, execution.Metadata(), arguments, options)
	h.appendRuleGeneration(result, err)
	return err
}

func (h *Handler) applyOrderTransforms(artifact *Artifact, object *coff.Object) error {
	goFirst := artifact.hasOption("+gofirst")
	optimize := artifact.hasOption("+optimize")
	disco := artifact.hasOption("+disco")
	if !goFirst && !optimize && !disco {
		return nil
	}
	exports := make([]string, 0, len(artifact.config.exports))
	for _, exported := range artifact.config.exports {
		exports = append(exports, exported.Symbol)
	}
	_, err := btf.ApplyOrderPasses(object, btf.OrderOptions{
		Entry:         entrySymbol(artifact),
		Exports:       exports,
		GoFirst:       goFirst,
		Optimize:      optimize,
		Disco:         disco,
		PreserveFirst: goFirst,
		Random:        h.random,
	})
	return err
}

func (a *Artifact) hasOption(option string) bool {
	_, ok := a.config.options[option]
	return ok
}

func entrySymbol(artifact *Artifact) string {
	if artifact.config.entrySet && artifact.config.entry == "" {
		// Empty entry is a supported way to disable upstream's conventional
		// go/_go lookup. COFF names cannot contain NUL, making this sentinel
		// unambiguous without expanding the linker API.
		return "\x00crystal-grotto-no-entry"
	}
	return artifact.config.entry
}

func applyPatches(object *coff.Object, patches []Patch) error {
	for _, patch := range patches {
		if err := validatePatch(object, patch.Symbol, patch.Data); err != nil {
			return err
		}
		symbol := object.GetSymbol(patch.Symbol)
		if err := symbol.Section.Patch(int(symbol.Value), patch.Data); err != nil {
			return err
		}
	}
	return nil
}

func mergeCOFFLinks(object *coff.Object, links []linker.LinkedSection) (*coff.Object, error) {
	if len(links) == 0 {
		return object, nil
	}
	objects := make([]*coff.Object, 0, len(links)+1)
	objects = append(objects, object)
	for index, linked := range links {
		additional, err := coff.NewObject(object.Machine)
		if err != nil {
			return nil, err
		}
		group := ".rdata"
		if linked.Executable {
			group = ".text"
		}
		section := coff.NewSection(fmt.Sprintf("%s$crystal_grotto_%08x", group, index), linked.Data)
		section.Alignment = linked.Alignment
		if section.Alignment == 0 {
			section.Alignment = 1
		}
		if err := additional.AddSection(section); err != nil {
			return nil, err
		}
		var symbol *coff.Symbol
		if linked.Executable {
			symbol = coff.NewFunctionSymbol(section, linked.Name, 0)
		} else {
			symbol = coff.NewDataSymbol(section, linked.Name, 0)
		}
		if err := additional.AddSymbol(symbol); err != nil {
			return nil, err
		}
		objects = append(objects, additional)
	}
	return linker.Merge(objects...)
}

func applyStrip(object *coff.Object, requested map[string]struct{}) error {
	if len(requested) == 0 {
		return nil
	}
	remove := make(map[string]struct{})
	for name := range requested {
		symbol := object.GetSymbol(name)
		if symbol == nil || symbol.IsSectionName() {
			continue
		}
		remove[name] = struct{}{}
	}
	if len(remove) == 0 {
		return nil
	}
	object.RemoveSymbols(remove)
	undefined := make(map[string]*coff.Symbol)
	for _, section := range object.Sections {
		for _, relocation := range section.Relocations {
			if _, stripped := remove[relocation.SymbolName]; !stripped {
				continue
			}
			symbol := undefined[relocation.SymbolName]
			if symbol == nil {
				symbol = &coff.Symbol{Name: relocation.SymbolName, StorageClass: coff.SymbolClassExternal}
				if err := object.AddSymbol(symbol); err != nil {
					return fmt.Errorf("re-add stripped relocation symbol %q: %w", symbol.Name, err)
				}
				undefined[symbol.Name] = symbol
			}
			relocation.Symbol = symbol
		}
	}
	return nil
}

func (h *Handler) writeDiagnostics(artifact *Artifact, object *coff.Object) error {
	if artifact.config.coffParse != nil {
		content := diagnosticTitle(artifact.config.coffParse.Title) + object.String()
		if err := h.writeDiagnostic(artifact.config.coffParse, []byte(content)); err != nil {
			return fmt.Errorf("coffparse output: %w", err)
		}
	}
	if artifact.config.disassemble == nil {
		return nil
	}
	text := object.GetSection(".text")
	if text == nil {
		return errors.New("disassemble output: object has no .text section")
	}
	ctx := context.Background()
	factory := h.newDisassembler
	if factory == nil {
		factory = defaultDisassemblerFactory
	}
	disassembler, err := factory(ctx, object.Machine)
	if err != nil {
		return fmt.Errorf("disassemble output: %w", err)
	}
	instructions, disassembleErr := disassembler.Disassemble(ctx, text.Data, 0)
	closeErr := disassembler.Close(ctx)
	if disassembleErr != nil {
		return fmt.Errorf("disassemble output: %w", disassembleErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close disassembler: %w", closeErr)
	}
	content := diagnosticTitle(artifact.config.disassemble.Title) + x86.Format(instructions, artifact.config.disassemble.ShowForms)
	if err := h.writeDiagnostic(artifact.config.disassemble, []byte(content)); err != nil {
		return fmt.Errorf("disassemble output: %w", err)
	}
	return nil
}

func diagnosticTitle(title string) string {
	if title == "" {
		return ""
	}
	return fmt.Sprintf("\n****************************************\n* %-36s *\n****************************************\n\n", title)
}

func (h *Handler) writeDiagnostic(output *DiagnosticOutput, content []byte) error {
	if output.Stdout {
		writer := h.stdout
		if writer == nil {
			writer = io.Discard
		}
		_, err := writer.Write(content)
		return err
	}
	if output.Path == "" {
		return errors.New("diagnostic output path is empty")
	}
	return os.WriteFile(output.Path, content, 0o644)
}
