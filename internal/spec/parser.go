// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

package spec

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/binutil"
)

var knownCommands = stringSet("export, generate, patch, preplen, prepsum, link, load, make, push, pop, xor, rc4, run, import, disassemble, coffparse, merge, reladdr, dfr, fixptrs, mergelib, fixbss, remap, attach, redirect, preserve, addhook, filterhooks, protect, exportfunc, optout, set, setg, foreach, echo, call, callnear, modcall, resolve, pack, linkfunc, next, rule, before, after, options, meta, ised, magic, entry, strip, linkpost, catch, intrinsic")

var metadataCommands = stringSet("describe, author, name, reference, license")
var zeroArgumentCommands = stringSet("export, preplen, prepsum, merge, options")
var oneArgumentCommands = stringSet("import, link, load, disassemble, coffparse, reladdr, fixptrs, fixbss, mergelib, protect, addhook, linkfunc, magic, entry, strip, push, pop, xor, rc4, filterhooks")
var twoArgumentCommands = stringSet("attach, redirect, remap, preserve, addhook, exportfunc, optout, load, patch, disassemble, coffparse, linkpost, catch, intrinsic")

var allowedOptions = map[string]map[string]struct{}{
	"make":        stringSet("+optimize,+disco,+mutate,+gofirst,+blockparty,+shatter,+regdance,+relax,+unwind"),
	"options":     stringSet("+optimize,+disco,+mutate,+gofirst,+blockparty,+shatter,+regdance,+relax,+unwind"),
	"disassemble": stringSet("+forms"),
	"ised":        stringSet("+before,+after,+first,+last,+split,+safe"),
	"dfr":         stringSet("+clear"),
}

// Metadata describes a specification file.
type Metadata struct {
	Author      string
	Name        string
	Description string
	Reference   string
	License     string
}

// Spec is a parsed Crystal Grotto specification. Parsed specs are immutable and
// can be executed concurrently by separate Runners.
type Spec struct {
	file     string
	metadata Metadata
	labels   map[string][]*Command
}

// File returns the filename associated with this specification.
func (s *Spec) File() string { return s.file }

// Metadata returns a copy of the specification metadata.
func (s *Spec) Metadata() Metadata { return s.metadata }

// Name returns explicitly configured metadata or derives a name from the file.
func (s *Spec) Name() string {
	if s.metadata.Name != "" {
		return s.metadata.Name
	}
	base := filepath.Base(s.file)
	if base == "loader.spec" {
		base = filepath.Base(filepath.Dir(s.file))
	}
	return strings.TrimSuffix(base, ".spec")
}

// Targets reports whether a non-empty program exists for label.
func (s *Spec) Targets(label string) bool { return len(s.labels[label]) != 0 }

// Labels returns the defined labels in source-independent order.
func (s *Spec) Labels() []string {
	labels := make([]string, 0, len(s.labels))
	for label := range s.labels {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels
}

// ParseError reports every independently discoverable syntax error in a spec.
type ParseError struct {
	File   string
	Errors []string
}

func (e *ParseError) Error() string {
	var result strings.Builder
	result.WriteString("Error(s) parsing ")
	result.WriteString(e.File)
	for _, item := range e.Errors {
		result.WriteString("\n* ")
		result.WriteString(item)
	}
	return result.String()
}

// Parse parses content as a Crystal Palace-compatible specification.
func Parse(file, content string) (*Spec, error) {
	p := parser{
		file: file,
		spec: &Spec{file: file, labels: make(map[string][]*Command)},
	}
	p.parse(content)
	if len(p.errors) != 0 {
		return nil, &ParseError{File: file, Errors: append([]string(nil), p.errors...)}
	}
	return p.spec, nil
}

type parser struct {
	file   string
	spec   *Spec
	errors []string
}

func (p *parser) error(line int, format string, args ...any) {
	p.errors = append(p.errors, fmt.Sprintf(format, args...)+fmt.Sprintf(" at line %d", line))
}

func (p *parser) parse(content string) {
	label := ""
	for index, original := range strings.Split(content, "\n") {
		lineNo := index + 1
		line := strings.TrimSpace(original)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, ":") && !strings.ContainsRune(line, ' ') {
			label = strings.TrimSuffix(line, ":")
			if strings.HasPrefix(label, ".") {
				p.error(lineNo, "Invalid label '%s' - acceptable labels are <name.>[x86|x64]<.o|.dll> - don't start name with a '.'", label)
			} else if !validLabel(label) {
				p.error(lineNo, "Invalid label '%s' - acceptable labels are <name.>[x86|x64]<.o|.dll>", label)
			}
			if len(p.spec.labels[label]) != 0 {
				p.error(lineNo, "Label %s is already defined", label)
			} else {
				p.spec.labels[label] = nil
			}
			continue
		}
		p.parseOne(label, line, lineNo)
	}
}

func (p *parser) parseOne(label, text string, line int) {
	command := ParseCommand(text)
	name := command.Name()
	args := command.RawArguments()

	if _, ok := metadataCommands[name]; ok {
		if len(args) == 0 {
			p.error(line, "Command '%s' requires an argument", name)
			return
		}
		p.setMetadata(name, args[0])
		return
	}
	if label == "" {
		p.error(line, "Commands must exist under an 'x86:' or 'x64:' label")
		return
	}
	if strings.HasPrefix(name, ".") {
		p.add(label, command)
		return
	}
	if _, ok := knownCommands[name]; !ok {
		p.error(line, "Invalid command '%s'", name)
		return
	}

	p.validateOptions(command, line)
	valid := false
	full, _ := command.FullCommand(nil)
	if _, ok := zeroArgumentCommands[name]; ok && len(args) == 0 {
		valid = true
	}
	if full == "make coff" || full == "make object" || full == "make pic" || full == "make pic64" {
		valid = true
	}
	if _, ok := oneArgumentCommands[name]; ok && len(args) == 1 {
		valid = true
	}
	if _, ok := twoArgumentCommands[name]; ok && len(args) == 2 {
		valid = true
	}

	switch name {
	case "dfr":
		if len(args) == 2 || len(args) == 3 {
			methods := stringSet("strings, ror13, djb2, fnv1a, sdbm")
			if _, ok := methods[args[1]]; ok {
				valid = true
			} else {
				p.error(line, "Invalid method '%s' for '%s'. Use 'ror13, djb2, fnv1a, sdbm' or 'strings'", args[1], command.Original())
				return
			}
		}
	case "generate":
		if len(args) == 2 {
			value, err := strconv.Atoi(args[1])
			if err != nil || value == -1 {
				p.error(line, "Invalid argument for '%s'. %s is not a valid number", command.Original(), args[1])
				return
			} else if value < 0 {
				p.error(line, "Invalid argument for '%s'. %s is a negative number", command.Original(), args[1])
				return
			} else if value == 0 {
				p.error(line, "Invalid argument for '%s'. %s is zero", command.Original(), args[1])
				return
			}
			valid = true
		}
	case "pack":
		valid = len(args) >= 2
	case "resolve", "set", "setg", "next":
		expected := 1
		if name == "set" || name == "setg" || name == "next" {
			expected = 2
		}
		if len(args) == expected {
			types := command.ArgumentTypes()
			if !strings.HasPrefix(args[0], "%") {
				p.error(line, "Invalid argument for '%s'. Try \"%%%s\"", command.Original(), args[0])
				return
			} else if len(types) == 0 || types[0] != "string" {
				p.error(line, "Quotes required for variable: %s \"%s\"", name, args[0])
				return
			}
			valid = true
			if name == "next" {
				p.add(label, command)
				p.parseOne(label, args[1], line)
				return
			}
		}
	case "meta":
		if len(args) == 2 {
			if _, ok := metadataCommands[args[0]]; !ok {
				p.error(line, "Invalid key '%s' for meta. Valid keys are author, describe, license, name, and reference.", args[0])
				return
			}
			valid = true
		}
	case "run":
		valid = len(args) >= 1
	case "call", "callnear":
		if len(args) >= 2 {
			if strings.HasPrefix(args[1], ".") {
				p.error(line, "Invalid label for '%s' - callable labels do not begin with a '.'", command.Original())
				return
			}
			if name == "callnear" {
				path := args[0]
				if !filepath.IsAbs(path) {
					path = filepath.Join(filepath.Dir(p.file), path)
				}
				canonical, err := filepath.Abs(path)
				if err != nil {
					p.error(line, "Could not canonicalize: %s(%s) for callnear", args[0], err)
					return
				}
				command = parseCommand(text, func(slot int, value string) string {
					switch slot {
					case 0:
						return "call"
					case 1:
						return canonical
					default:
						return value
					}
				})
			}
			valid = true
		}
	case "echo":
		valid = len(args) >= 1
	case "before", "after":
		if len(args) >= 2 {
			if err := validateHookArguments(args); err != nil {
				p.error(line, "%s in %s", err, command.Original())
				return
			}
			valid = true
			p.add(label, command)
			p.parseOne(label, args[len(args)-1], line)
			return
		}
	case "foreach":
		if len(args) == 2 {
			valid = true
			p.add(label, command)
			p.parseOne(label, args[1], line)
			return
		}
	case "rule":
		if len(args) >= 1 {
			if err := validateRuleArguments(args); err != nil {
				p.error(line, "%s", err)
				return
			}
			valid = true
		}
	case "ised":
		if len(args) >= 1 {
			if err := validateRewriteArguments(args, command); err != nil {
				p.error(line, "%s", err)
				return
			}
			valid = true
		}
	}

	if valid {
		p.add(label, command)
		return
	}
	hint := commandHint(name)
	if len(args) == 0 {
		p.error(line, "Command %s missing arguments, try '%s'", name, hint)
	} else {
		p.error(line, "Command %s invalid arguments, try '%s'", name, hint)
	}
}

func (p *parser) validateOptions(command *Command, line int) {
	if !command.HasOptions() {
		return
	}
	allowed, ok := allowedOptions[command.Name()]
	if !ok {
		p.error(line, "Command '%s' does not accept +options %v", command.Name(), command.Options())
		return
	}
	for _, option := range command.Options() {
		if _, ok := allowed[option]; !ok {
			full, _ := command.FullCommand(nil)
			p.error(line, "Invalid option %s for '%s'", option, full)
		}
	}
	if command.HasOption("+unwind") && command.HasOption("+shatter") {
		full, _ := command.FullCommand(nil)
		p.error(line, "Options +shatter and +unwind are not compatible in '%s'", full)
	}
}

func (p *parser) add(label string, command *Command) {
	p.spec.labels[label] = append(p.spec.labels[label], command)
}

func (p *parser) setMetadata(name, value string) {
	switch name {
	case "author":
		p.spec.metadata.Author = value
	case "describe":
		p.spec.metadata.Description = value
	case "license":
		p.spec.metadata.License = value
	case "name":
		p.spec.metadata.Name = value
	case "reference":
		p.spec.metadata.Reference = value
	}
}

func validLabel(label string) bool {
	for _, suffix := range []string{"x86", "x64", "x86.o", "x64.o", "x86.dll", "x64.dll"} {
		if label == suffix || strings.HasSuffix(label, "."+suffix) {
			return true
		}
	}
	return false
}

func validateHookArguments(args []string) error {
	command := args[0]
	if command == "echo" || command == "before" || command == "after" {
		return fmt.Errorf("Command %s is an invalid .spec hook target", command)
	}
	filters := args[1 : len(args)-1]
	if len(filters) > 0 && filters[0] != "" {
		if _, ok := stringSet("bytes,pic,coff,object")[filters[0]]; !ok {
			return fmt.Errorf("Type %s is invalid. Use: bytes, pic, coff, or object", filters[0])
		}
	}
	if len(filters) > 2 && filters[2] != "" && !validLabel(filters[2]) {
		return fmt.Errorf("Label %s isn't arch.o, arch.dll, arch, or *.[one of those]", filters[2])
	}
	return nil
}

func validateRuleArguments(args []string) error {
	maxRules := int64(10)
	agreement := int64(5)
	if len(args) > 1 {
		value, err := strconv.ParseInt(args[1], 10, 32)
		if err != nil || value == -1 {
			return fmt.Errorf("maxrules must be integer: %s", args[1])
		}
		maxRules = value
	}
	if len(args) > 2 {
		value, err := strconv.ParseInt(args[2], 10, 32)
		if err != nil || value == -1 {
			return fmt.Errorf("minagree must be integer: %s", args[2])
		}
		agreement = value
	}
	if len(args) > 3 {
		if _, err := binutil.ParseRange(args[3]); err != nil {
			return err
		}
	}
	if maxRules > 0 && agreement > maxRules {
		return fmt.Errorf("agreement %d is larger than max rules %d. That won't fly", agreement, maxRules)
	}
	return nil
}

func validateRewriteArguments(args []string, command *Command) error {
	if args[0] != "insert" && args[0] != "replace" {
		return fmt.Errorf("ised: Invalid verb '%s'. Use insert or replace", args[0])
	}
	if len(args) < 2 || args[len(args)-1] == "" {
		return fmt.Errorf("ised: Specify a variable $VAR as the last parameter")
	}
	if len(args) < 3 {
		return fmt.Errorf("ised: Missing pattern arguments. Specify as \"push rbx\" (specific) or \"PUSH r64\" (generic)")
	}
	if command.HasOption("+first") && command.HasOption("+last") {
		return fmt.Errorf("ised: both +first and +last set. Pick one. I can't act on both.")
	}
	if command.HasOption("+before") && command.HasOption("+after") {
		return fmt.Errorf("ised: both +before and +after set. Pick one. I can't act on both.")
	}
	return nil
}

func commandHint(name string) string {
	hints := map[string]string{
		"export": "export", "generate": "generate $KEY 1024", "link": "link 'section_name'",
		"linkfunc": "linkfunc 'symbol'", "load": "load 'path/to/file'", "run": "run 'path/to/file' [args...]",
		"call": "call 'path/to/file' 'name' [args...]", "callnear": "callnear 'path/to/file' 'name' [args...]",
		"mergelib": "mergelib 'path/to/file.zip'", "make": "make pic, make coff, make object",
		"push": "push $DLL", "pop": "push $VAR", "xor": "xor $KEY", "rc4": "rc4 $KEY",
		"pack": "pack $DEST 'template' 'arg1' 'arg2' ...", "echo": "echo 'message'",
		"set": "set '%var' 'value'", "setg": "setg '%var' 'value'", "resolve": "resolve '%var'",
		"foreach": "foreach 'val1, val2': command %_", "next": "next '%var': command %_",
		"before": "before 'cmd1': cmd2 %_", "after": "after 'cmd1': cmd2 %_",
		"entry": "entry '_gtfo'", "catch": "catch 'function' 'handler'", "intrinsic": "intrinsic '__function' $VAR",
	}
	return hints[name]
}

func stringSet(values string) map[string]struct{} {
	result := make(map[string]struct{})
	if values == "" {
		return result
	}
	for _, value := range strings.Split(values, ",") {
		result[strings.TrimSpace(value)] = struct{}{}
	}
	return result
}
