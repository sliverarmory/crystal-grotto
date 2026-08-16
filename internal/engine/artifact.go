// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

// Package engine connects the specification VM's object stack to the COFF
// model and deterministic linker implementations.
package engine

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	hookmodel "github.com/sliverarmory/crystal-grotto/internal/hooks"
	"github.com/sliverarmory/crystal-grotto/internal/ised"
	"github.com/sliverarmory/crystal-grotto/internal/linker"
	"github.com/sliverarmory/crystal-grotto/internal/resolver"
)

// Kind is the value exposed to Crystal Palace hooks through StackValue.Type.
type Kind string

const (
	KindCOFF   Kind = "coff"
	KindObject Kind = "object"
	KindPIC    Kind = "pic"
	KindPIC64  Kind = "pic64"
)

// DiagnosticOutput describes a coffparse or disassemble output registered by
// a specification. Path is absolute unless Stdout is true.
type DiagnosticOutput struct {
	Path      string
	Title     string
	ShowForms bool
	Stdout    bool
}

// Patch is one deferred symbol patch. Data owns its backing storage.
type Patch struct {
	Symbol string
	Data   []byte
}

// DeferredCommand records configuration for an upstream transformation or
// hook that is not implemented yet. AffectsProgram prevents export from
// silently producing bytes without applying the command.
type DeferredCommand struct {
	Name           string
	Arguments      []string
	Options        []string
	AffectsProgram bool
}

// Configuration is a defensive snapshot of an Artifact's export settings.
type Configuration struct {
	Entry         string
	EntrySet      bool
	Options       []string
	Strip         []string
	Patches       []Patch
	Links         []linker.LinkedSection
	LinkPosts     []string
	APIs          []string
	Exports       []linker.Export
	Magic         []uint32
	RuleArguments []string
	GetBSS        string
	ReturnAddress string
	Hooks         hookmodel.Snapshot
	ISED          ised.Configuration
	Resolvers     resolver.Configuration
	COFFParse     *DiagnosticOutput
	Disassemble   *DiagnosticOutput
	Deferred      []DeferredCommand
}

// Artifact is the object value carried on the specification VM stack.
// Mutations are request-local because each make command constructs a new
// Artifact from independently parsed bytes.
type Artifact struct {
	kind   Kind
	object *coff.Object
	config artifactConfig
}

type artifactConfig struct {
	entry    string
	entrySet bool

	options map[string]struct{}
	strip   map[string]struct{}

	patches       []Patch
	patchIndex    map[string]int
	links         []linker.LinkedSection
	linkIndex     map[string]int
	linkPosts     []string
	linkPostIndex map[string]int
	apis          []string
	exports       []linker.Export
	exportIndex   map[string]int
	magic         []uint32
	ruleArguments []string
	getBSS        string
	returnAddress string
	hooks         *hookmodel.Model
	ised          ised.Configuration
	resolvers     resolver.Configuration

	coffParse   *DiagnosticOutput
	disassemble *DiagnosticOutput
	deferred    []DeferredCommand
}

func newArtifact(kind Kind, object *coff.Object) *Artifact {
	entry := "go"
	if object != nil && object.Machine == coff.MachineI386 {
		entry = "_go"
	}
	hooks, _ := hookmodel.New(object)
	return &Artifact{
		kind:   kind,
		object: object,
		config: artifactConfig{
			entry:         entry,
			options:       make(map[string]struct{}),
			strip:         make(map[string]struct{}),
			patchIndex:    make(map[string]int),
			linkIndex:     make(map[string]int),
			linkPostIndex: make(map[string]int),
			exportIndex:   make(map[string]int),
			apis:          []string{"LoadLibraryA", "GetProcAddress"},
			hooks:         hooks,
			ised:          ised.EmptyConfiguration(),
			resolvers:     resolver.EmptyConfiguration(),
		},
	}
}

// Type implements the stack object's upstream-visible type contract.
func (a *Artifact) Type() string {
	if a == nil {
		return "object"
	}
	return string(a.kind)
}

// Kind returns the artifact's output kind.
func (a *Artifact) Kind() Kind {
	if a == nil {
		return ""
	}
	return a.kind
}

// COFF returns the request-local COFF model. It is intended for adapter and
// diagnostic integrations; callers must not share it across requests.
func (a *Artifact) COFF() *coff.Object {
	if a == nil {
		return nil
	}
	return a.object
}

// Configuration returns a defensive, deterministic configuration snapshot.
func (a *Artifact) Configuration() Configuration {
	if a == nil {
		return Configuration{}
	}
	configuration := Configuration{
		Entry:         a.config.entry,
		EntrySet:      a.config.entrySet,
		Options:       sortedKeys(a.config.options),
		Strip:         sortedKeys(a.config.strip),
		Patches:       clonePatches(a.config.patches),
		Links:         cloneLinks(a.config.links),
		LinkPosts:     append([]string(nil), a.config.linkPosts...),
		APIs:          append([]string(nil), a.config.apis...),
		Exports:       append([]linker.Export(nil), a.config.exports...),
		Magic:         append([]uint32(nil), a.config.magic...),
		RuleArguments: append([]string(nil), a.config.ruleArguments...),
		GetBSS:        a.config.getBSS,
		ReturnAddress: a.config.returnAddress,
		ISED:          a.config.ised,
		Resolvers:     a.config.resolvers,
		COFFParse:     cloneDiagnostic(a.config.coffParse),
		Disassemble:   cloneDiagnostic(a.config.disassemble),
		Deferred:      cloneDeferred(a.config.deferred),
	}
	if a.config.hooks != nil {
		configuration.Hooks = a.config.hooks.Snapshot()
	}
	return configuration
}

func (a *Artifact) addOptions(options []string) {
	for _, option := range options {
		a.config.options[option] = struct{}{}
	}
}

func (a *Artifact) addStrip(names []string) {
	for _, name := range names {
		a.config.strip[name] = struct{}{}
	}
}

func (a *Artifact) setPatch(symbol string, data []byte) {
	patch := Patch{Symbol: symbol, Data: append([]byte(nil), data...)}
	if index, ok := a.config.patchIndex[symbol]; ok {
		a.config.patches[index] = patch
		return
	}
	a.config.patchIndex[symbol] = len(a.config.patches)
	a.config.patches = append(a.config.patches, patch)
}

func (a *Artifact) setLink(link linker.LinkedSection) {
	link.Data = append([]byte(nil), link.Data...)
	link.Relocations = append([]linker.LinkedRelocation(nil), link.Relocations...)
	if index, ok := a.config.linkIndex[link.Name]; ok {
		a.config.links[index] = link
		return
	}
	a.config.linkIndex[link.Name] = len(a.config.links)
	a.config.links = append(a.config.links, link)
}

func (a *Artifact) setLinkPost(name string) {
	if index, ok := a.config.linkPostIndex[name]; ok {
		a.config.linkPosts[index] = name
		return
	}
	a.config.linkPostIndex[name] = len(a.config.linkPosts)
	a.config.linkPosts = append(a.config.linkPosts, name)
}

func (a *Artifact) setExport(export linker.Export) error {
	for _, existing := range a.config.exports {
		if existing.Tag == export.Tag {
			return fmt.Errorf("export tag %#08x for %s conflicts with %s", export.Tag, export.Symbol, existing.Symbol)
		}
	}
	if index, ok := a.config.exportIndex[export.Symbol]; ok {
		a.config.exports[index] = export
		return nil
	}
	a.config.exportIndex[export.Symbol] = len(a.config.exports)
	a.config.exports = append(a.config.exports, export)
	return nil
}

func (a *Artifact) deferCommand(command DeferredCommand) {
	command.Arguments = append([]string(nil), command.Arguments...)
	command.Options = append([]string(nil), command.Options...)
	a.config.deferred = append(a.config.deferred, command)
}

func (a *Artifact) setRuleArguments(arguments []string) {
	a.config.ruleArguments = append([]string(nil), arguments...)
}

// ErrUnsupported identifies a configured feature whose implementation is not
// present. errors.Is can be used without matching error text.
var ErrUnsupported = errors.New("engine feature is not implemented")

// UnsupportedError lists every configured feature that would otherwise be
// silently omitted from an export.
type UnsupportedError struct {
	Features []string
}

func (e *UnsupportedError) Error() string {
	features := append([]string(nil), e.Features...)
	sort.Strings(features)
	return "engine: unsupported configured feature(s): " + strings.Join(features, ", ")
}

func (e *UnsupportedError) Unwrap() error { return ErrUnsupported }

func (a *Artifact) unsupportedError() error {
	features := make(map[string]struct{})
	for option := range a.config.options {
		if _, supported := supportedTransformOptions[option]; !supported {
			features[option] = struct{}{}
		}
	}
	for _, command := range a.config.deferred {
		if command.AffectsProgram {
			features[command.Name] = struct{}{}
		}
	}
	if len(features) == 0 {
		return nil
	}
	return &UnsupportedError{Features: sortedKeys(features)}
}

var supportedTransformOptions = map[string]struct{}{
	"+blockparty": {},
	"+disco":      {},
	"+gofirst":    {},
	"+mutate":     {},
	"+optimize":   {},
	"+regdance":   {},
	"+relax":      {},
	"+shatter":    {},
	"+unwind":     {},
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func clonePatches(values []Patch) []Patch {
	result := make([]Patch, len(values))
	for index, value := range values {
		result[index] = Patch{Symbol: value.Symbol, Data: append([]byte(nil), value.Data...)}
	}
	return result
}

func cloneLinks(values []linker.LinkedSection) []linker.LinkedSection {
	result := make([]linker.LinkedSection, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Data = append([]byte(nil), value.Data...)
		result[index].Relocations = append([]linker.LinkedRelocation(nil), value.Relocations...)
	}
	return result
}

func cloneDiagnostic(value *DiagnosticOutput) *DiagnosticOutput {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneDeferred(values []DeferredCommand) []DeferredCommand {
	result := make([]DeferredCommand, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Arguments = append([]string(nil), value.Arguments...)
		result[index].Options = append([]string(nil), value.Options...)
	}
	return result
}
