// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

package engine

import (
	"archive/zip"
	"fmt"
	"io"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/linker"
	"github.com/sliverarmory/crystal-grotto/internal/spec"
)

const maximumLibraryMemberBytes int64 = 512 << 20

func (h *Handler) handleMergeLibrary(context *spec.ExecutionContext, command *spec.Command, arguments []string) error {
	if err := requireArguments(command.Name(), arguments, 1, 1); err != nil {
		return err
	}
	path, err := context.ResolveFile(arguments[0])
	if err != nil {
		return simplifyProgramError(err)
	}
	archive, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("open COFF library %s: %w", path, err)
	}
	defer archive.Close()

	objects := make([]*coff.Object, 0, len(archive.File)+1)
	for _, entry := range archive.File {
		if entry.UncompressedSize64 > uint64(maximumLibraryMemberBytes) {
			return fmt.Errorf("COFF library member %q is %d bytes; maximum is %d", entry.Name, entry.UncompressedSize64, maximumLibraryMemberBytes)
		}
		reader, err := entry.Open()
		if err != nil {
			return fmt.Errorf("open COFF library member %q: %w", entry.Name, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, maximumLibraryMemberBytes+1))
		closeErr := reader.Close()
		if readErr != nil {
			return fmt.Errorf("read COFF library member %q: %w", entry.Name, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close COFF library member %q: %w", entry.Name, closeErr)
		}
		if int64(len(data)) > maximumLibraryMemberBytes {
			return fmt.Errorf("COFF library member %q exceeds %d bytes", entry.Name, maximumLibraryMemberBytes)
		}
		object, err := coff.Parse(data)
		if err != nil {
			return fmt.Errorf("parse COFF library member %q: %w", entry.Name, err)
		}
		if object.Architecture() != context.Arch() {
			return fmt.Errorf("%s COFF arch differs from %s .spec target", object.Architecture(), context.Target())
		}
		objects = append(objects, object)
	}

	artifact, value, err := popArtifact(context)
	if err != nil {
		return err
	}
	if artifact.hasOption("+relax") {
		for _, object := range objects {
			if _, err := coff.RelaxReferencePointers(object); err != nil {
				return err
			}
		}
	}
	// Upstream reads every ZIP entry and lets COFFMerge skip only objects whose
	// external definitions are already represented. It does not use the usual
	// unresolved-symbol archive selection algorithm.
	objects = append([]*coff.Object{artifact.object}, objects...)
	merged, err := linker.Merge(objects...)
	if err != nil {
		return err
	}
	artifact.object = merged
	context.Push(spec.StackValue{Object: artifact, Source: value.Source})
	return nil
}
