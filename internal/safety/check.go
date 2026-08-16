// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package safety

import (
	"context"
	"errors"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

// Check builds a conservative graph and validates one or more helper roots.
// Root order is observable when multiple unsafe paths exist.
func Check(ctx context.Context, object *coff.Object, roots []string, options Options) (Report, error) {
	graph, err := BuildGraph(ctx, object, options)
	if err != nil {
		return Report{}, err
	}
	return graph.Check(ctx, roots...)
}

// CheckRoot is the single-helper convenience form of Check.
func CheckRoot(ctx context.Context, object *coff.Object, root string, options Options) (Report, error) {
	return Check(ctx, object, []string{root}, options)
}

// Check walks previously built graph state from roots. The method allocates
// all traversal state per call and is safe for concurrent use.
func (g *Graph) Check(ctx context.Context, roots ...string) (Report, error) {
	if ctx == nil {
		return Report{}, analysisError("walk input validation", "", 0, false, x86.ErrNilContext)
	}
	if err := ctx.Err(); err != nil {
		return Report{}, analysisError("walk input validation", "", 0, false, err)
	}
	if g == nil {
		return Report{}, analysisError("walk input validation", "", 0, false, errors.New("nil graph"))
	}
	if len(roots) == 0 {
		return Report{}, analysisError("walk input validation", "", 0, false, errors.New("at least one helper root is required"))
	}
	report := Report{}
	seenRoots := make(map[string]bool, len(roots))
	for _, root := range roots {
		if root == "" {
			return Report{}, analysisError("walk input validation", "", 0, false, errors.New("helper root is empty"))
		}
		if seenRoots[root] {
			continue
		}
		if !g.rootable[root] {
			return Report{}, analysisError("walk input validation", root, 0, false, errors.New("helper root is not a local .text function"))
		}
		seenRoots[root] = true
		report.Roots = append(report.Roots, root)
	}

	reported := make(map[string]bool)
	for _, root := range report.Roots {
		visited := make(map[string]bool)
		var walk func(string, []string) error
		walk = func(function string, chain []string) error {
			if err := ctx.Err(); err != nil {
				return analysisError("danger walk", function, 0, false, err)
			}
			if visited[function] {
				return nil
			}
			visited[function] = true
			if !reported[function] {
				reported[function] = true
				report.Visited = append(report.Visited, function)
			}
			chain = append(append([]string(nil), chain...), function)
			if dangerSymbol(g.machine, function) {
				return &DangerError{Root: root, Parent: function, Symbol: dangerName(g.machine), Chain: append([]string(nil), chain...), Machine: g.machine}
			}
			for _, edge := range g.adjacency[function] {
				if err := ctx.Err(); err != nil {
					return analysisError("danger walk", function, edge.Offset, true, err)
				}
				if dangerSymbol(g.machine, edge.To) {
					return &DangerError{
						Root:    root,
						Parent:  function,
						Symbol:  dangerName(g.machine),
						Chain:   append([]string(nil), chain...),
						Machine: g.machine,
					}
				}
				if _, exists := g.adjacency[edge.To]; !exists {
					return analysisError("danger walk", function, edge.Offset, true, errors.New("local graph edge has no target node"))
				}
				if err := walk(edge.To, chain); err != nil {
					return err
				}
			}
			return nil
		}
		if err := walk(root, nil); err != nil {
			return Report{}, err
		}
	}
	return Report{
		Roots:   append([]string(nil), report.Roots...),
		Visited: append([]string(nil), report.Visited...),
	}, nil
}

func dangerName(machine coff.Machine) string {
	if machine == coff.MachineI386 {
		return "_dprintf"
	}
	return "dprintf"
}

func dangerSymbol(machine coff.Machine, symbol string) bool {
	want := dangerName(machine)
	if symbol == want {
		return true
	}
	if strings.HasPrefix(symbol, "__imp_") {
		return strings.TrimPrefix(symbol, "__imp_") == want
	}
	if strings.HasPrefix(symbol, "_imp__") {
		return strings.TrimPrefix(symbol, "_imp__") == want
	}
	return false
}
