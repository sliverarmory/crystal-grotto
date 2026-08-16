// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

package spec

import (
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Environment holds byte variables ($NAME) and string variables (%name).
type Environment map[string]any

// Bytes returns a defensive copy of a byte variable.
func (e Environment) Bytes(key string) ([]byte, error) {
	if !strings.HasPrefix(key, "$") {
		return nil, fmt.Errorf("Invalid argument. Try: $%s", key)
	}
	if key == "$NULL" {
		return []byte{}, nil
	}
	value, ok := e[key]
	if !ok {
		return nil, fmt.Errorf("Var %s is not set", key)
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("Var %s is not a byte[]", key)
	}
	return append([]byte(nil), bytes...), nil
}

func (e Environment) putBytes(key string, value []byte) error {
	if !strings.HasPrefix(key, "$") {
		return fmt.Errorf("Invalid argument. Try: $%s", key)
	}
	if _, exists := e[key]; exists && (key == "$DLL" || key == "$OBJECT" || key == "$NULL") {
		return fmt.Errorf("%s is immutable in environment. Can't overwrite", key)
	}
	e[key] = append([]byte(nil), value...)
	return nil
}

// MessageType classifies messages emitted by a specification.
type MessageType uint8

const (
	MessageEcho MessageType = iota
	MessageWarning
)

// Message is output emitted by a specification program.
type Message struct {
	Type   MessageType
	Text   string
	File   string
	Target string
}

func (m Message) String() string { return fmt.Sprintf("%s in %s (%s)", m.Text, m.File, m.Target) }

// Logger receives echo and warning messages.
type Logger interface {
	LogSpecMessage(Message)
}

// LoggerFunc adapts a function to Logger.
type LoggerFunc func(Message)

func (f LoggerFunc) LogSpecMessage(message Message) { f(message) }

// StackValue is a typed VM stack item. Object is reserved for the linker layer.
type StackValue struct {
	Data   []byte
	Object any
	Source string
}

// Type returns the upstream-visible type name for hooks and diagnostics.
func (v StackValue) Type() string {
	if v.Object == nil {
		return "bytes"
	}
	if typed, ok := v.Object.(interface{ Type() string }); ok {
		return typed.Type()
	}
	return "object"
}

// CommandHandler implements linker/object commands outside the spec VM.
type CommandHandler interface {
	Handle(*ExecutionContext, *Command, []string) (bool, error)
}

// RuleProvider is implemented by handlers that generate YARA rules while a
// specification executes.
type RuleProvider interface {
	GeneratedRules() ([]byte, error)
}

// RuleGenerationRequester is implemented by handlers that need an explicit
// signal before execution when the caller selected RunAndGenerate. Upstream
// uses the presence of a global rule-output handle for the same purpose.
type RuleGenerationRequester interface {
	RequestRuleGeneration()
}

// ExecutionContext exposes controlled VM state to a linker command handler.
type ExecutionContext struct{ vm *vm }

func (c *ExecutionContext) Arch() string             { return c.vm.arch }
func (c *ExecutionContext) Target() string           { return c.vm.target }
func (c *ExecutionContext) Metadata() Metadata       { return *c.vm.metadata }
func (c *ExecutionContext) Environment() Environment { return c.vm.session.env }
func (c *ExecutionContext) Pop() (StackValue, error) { return c.vm.pop() }
func (c *ExecutionContext) Push(value StackValue)    { c.vm.push(value) }
func (c *ExecutionContext) Peek() *StackValue        { return c.vm.peek() }
func (c *ExecutionContext) ResolveFile(path string) (string, error) {
	return c.vm.resolveInputFile(path)
}

// RunOptions customize one independent execution session.
type RunOptions struct {
	Environment Environment
	Logger      Logger
	Random      io.Reader
	Handler     CommandHandler
}

// Result contains program bytes and optional generated rules.
type Result struct {
	Program []byte
	Rules   []byte
}

// Run executes a specification and requires exactly one byte value on the stack.
func (s *Spec) Run(capability Capability, options RunOptions) ([]byte, error) {
	session := newSession(capability, options)
	metadata := s.metadata
	root := &vm{spec: s, session: session, arch: capability.Arch, capabilityLabel: capability.Label, locals: make(map[string]string), metadata: &metadata}
	if err := root.runTarget(""); err != nil {
		return nil, err
	}
	if len(session.stack) == 0 {
		return nil, root.programError("Stack is empty. Where's the bytes I want to return?")
	}
	value, err := root.pop()
	if err != nil {
		return nil, err
	}
	if len(session.stack) != 0 {
		return nil, root.programError("Stack is not empty. Make sure all objects are processed")
	}
	if value.Object != nil {
		return nil, root.programError("POP expected BYTES, received " + value.Type())
	}
	return append([]byte(nil), value.Data...), nil
}

// RunAndGenerate executes a spec and returns program/rule outputs. Rule output is
// populated by linker handlers that support rule generation.
func (s *Spec) RunAndGenerate(capability Capability, options RunOptions) (Result, error) {
	if requester, ok := options.Handler.(RuleGenerationRequester); ok {
		requester.RequestRuleGeneration()
	}
	program, err := s.Run(capability, options)
	if err != nil {
		return Result{}, err
	}
	result := Result{Program: program}
	if provider, ok := options.Handler.(RuleProvider); ok {
		rules, err := provider.GeneratedRules()
		if err != nil {
			return Result{}, err
		}
		result.Rules = append([]byte(nil), rules...)
	}
	return result, nil
}

// RunConfig executes a configuration specification and requires an empty stack.
func (s *Spec) RunConfig(capability Capability, options RunOptions) (Environment, error) {
	session := newSession(capability, options)
	metadata := s.metadata
	root := &vm{spec: s, session: session, arch: capability.Arch, capabilityLabel: capability.Label, locals: make(map[string]string), metadata: &metadata}
	if err := root.runTarget(""); err != nil {
		return nil, err
	}
	if len(session.stack) != 0 {
		return nil, root.programError("Stack is not empty. Make sure all objects are processed")
	}
	return session.env, nil
}

type session struct {
	stack     []StackValue
	env       Environment
	logger    Logger
	random    io.Reader
	handler   CommandHandler
	before    map[string][]hook
	after     map[string][]hook
	hookDepth int
}

func newSession(capability Capability, options RunOptions) *session {
	env := options.Environment
	if env == nil {
		env = make(Environment)
	}
	if capability.HasCapability() {
		env[capability.Key] = append([]byte(nil), capability.Contents...)
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	return &session{env: env, logger: options.Logger, random: random, handler: options.Handler, before: make(map[string][]hook), after: make(map[string][]hook)}
}

type vm struct {
	spec            *Spec
	session         *session
	locals          map[string]string
	arch            string
	capabilityLabel string
	target          string
	lastCommand     string
	lastVariables   map[string]string
	lastArgument    *StackValue
	metadata        *Metadata
}

type hook struct {
	command  string
	typeName string
	file     string
	label    string
	action   *Command
}

func (v *vm) runTarget(name string) error {
	target, err := v.callTarget(name)
	if err != nil {
		return v.programError(err.Error())
	}
	previous := v.target
	v.target = target
	defer func() { v.target = previous }()
	if err := v.runHooks(v.session.before[""], nil, nil); err != nil {
		return err
	}
	commands := v.spec.labels[target]
	for index := 0; index < len(commands); index++ {
		v.lastCommand = commands[index].Original()
		if err := v.runCommand(commands, &index); err != nil {
			return err
		}
	}
	return v.runHooks(v.session.after[""], nil, nil)
}

func (v *vm) callTarget(name string) (string, error) {
	candidates := []string{v.capabilityLabel, v.arch}
	if name != "" {
		candidates = []string{name + "." + v.capabilityLabel, name + "." + v.arch}
	}
	for _, candidate := range candidates {
		if v.spec.Targets(candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("Spec does not have target for '%s' or '%s'", candidates[0], candidates[1])
}

func (v *vm) runCommand(commands []*Command, index *int) error {
	command := commands[*index]
	resolved, err := command.Arguments(v)
	if err != nil {
		return v.programError(err.Error())
	}
	v.lastVariables = resolved.Variables
	args := resolved.Args
	if err := v.runHooks(v.session.before[command.Name()], command, args); err != nil {
		return err
	}

	name := command.Name()
	if strings.HasPrefix(name, ".") {
		child := *v
		child.locals = positionalLocals(args)
		if err := child.runTarget(strings.TrimPrefix(name, ".")); err != nil {
			return err
		}
		return v.runHooks(v.session.after[name], command, args)
	}

	handled := true
	switch name {
	case "load":
		if len(args) == 1 {
			path, err := v.resolveInputFile(args[0])
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return v.programError(err.Error())
			}
			v.push(StackValue{Data: data, Source: filepath.Base(path)})
		} else {
			path, err := v.resolveInputFile(args[1])
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return v.programError(err.Error())
			}
			if err := v.session.env.putBytes(args[0], data); err != nil {
				return v.programError(err.Error())
			}
		}
	case "run", "call":
		path, err := v.resolveInputFile(args[0])
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return v.programError(err.Error())
		}
		childSpec, err := Parse(path, string(content))
		if err != nil {
			return err
		}
		metadata := childSpec.metadata
		child := &vm{spec: childSpec, session: v.session, arch: v.arch, capabilityLabel: v.capabilityLabel, locals: make(map[string]string), metadata: &metadata}
		target := ""
		if name == "run" {
			child.locals = positionalLocals(args[1:])
		} else {
			target = args[1]
			child.locals = positionalLocals(args[2:])
		}
		if err := child.runTarget(target); err != nil {
			return err
		}
	case "meta":
		setMetadata(v.metadata, args[0], args[1])
	case "setg":
		v.session.env[args[0]] = args[1]
	case "set":
		v.locals[args[0]] = args[1]
	case "resolve":
		value, err := v.Resolve(args[0])
		if err != nil {
			return v.programError(err.Error())
		}
		items := splitList(value)
		for i, item := range items {
			path := item
			if !filepath.IsAbs(path) {
				path = filepath.Join(filepath.Dir(v.spec.file), path)
			}
			items[i], err = filepath.Abs(path)
			if err != nil {
				return v.programError(err.Error() + ": " + path)
			}
		}
		if _, ok := v.locals[args[0]]; ok {
			v.locals[args[0]] = strings.Join(items, ", ")
		} else {
			v.session.env[args[0]] = strings.Join(items, ", ")
		}
	case "pack":
		data, err := pack(args[1], v.arch, args[2:], v.session.env)
		if err != nil {
			return v.programError(err.Error())
		}
		if err := v.session.env.putBytes(args[0], data); err != nil {
			return v.programError(err.Error())
		}
	case "generate":
		length, _ := strconv.Atoi(args[1])
		data := make([]byte, length)
		if _, err := io.ReadFull(v.session.random, data); err != nil {
			return v.programError(err.Error())
		}
		if err := v.session.env.putBytes(args[0], data); err != nil {
			return v.programError(err.Error())
		}
	case "push":
		data, err := v.session.env.Bytes(args[0])
		if err != nil {
			return v.programError(err.Error())
		}
		v.push(StackValue{Data: data, Source: args[0]})
	case "pop":
		value, err := v.popBytes()
		if err != nil {
			return err
		}
		if err := v.session.env.putBytes(args[0], value.Data); err != nil {
			return v.programError(err.Error())
		}
	case "xor", "rc4":
		value, err := v.popBytes()
		if err != nil {
			return err
		}
		key, err := v.session.env.Bytes(args[0])
		if err != nil {
			return v.programError(err.Error())
		}
		if len(key) == 0 {
			return v.programError(name + " key is empty")
		}
		data := append([]byte(nil), value.Data...)
		if name == "xor" {
			for i := range data {
				data[i] ^= key[i%len(key)]
			}
		} else {
			cipher, err := rc4.NewCipher(key)
			if err != nil {
				return v.programError(err.Error())
			}
			cipher.XORKeyStream(data, data)
		}
		v.push(StackValue{Data: data, Source: value.Source})
	case "preplen", "prepsum":
		value, err := v.popBytes()
		if err != nil {
			return err
		}
		data := make([]byte, 4, len(value.Data)+4)
		if name == "preplen" {
			binary.LittleEndian.PutUint32(data, uint32(len(value.Data)))
		} else {
			binary.LittleEndian.PutUint32(data, adler32.Checksum(value.Data))
		}
		data = append(data, value.Data...)
		v.push(StackValue{Data: data, Source: value.Source})
	case "echo":
		v.log(MessageEcho, strings.Join(args, " "))
	case "before", "after":
		if *index+1 >= len(commands) {
			return v.programError(name + " is missing its action")
		}
		(*index)++
		h := makeHook(args, commands[*index])
		if name == "before" {
			v.session.before[h.command] = append(v.session.before[h.command], h)
		} else {
			v.session.after[h.command] = append(v.session.after[h.command], h)
		}
	case "foreach", "next":
		if *index+1 >= len(commands) {
			return v.programError(name + " is missing its action")
		}
		(*index)++
		actionIndex := *index
		if name == "foreach" {
			for _, value := range splitList(args[0]) {
				v.locals["%_"] = value
				localIndex := actionIndex
				if err := v.runCommand(commands, &localIndex); err != nil {
					return err
				}
			}
		} else {
			value, ok, err := v.shift(args[0])
			if err != nil {
				return v.programError(err.Error())
			}
			if ok && value != "" {
				v.locals["%_"] = value
				localIndex := actionIndex
				if err := v.runCommand(commands, &localIndex); err != nil {
					return err
				}
			}
		}
		delete(v.locals, "%_")
	default:
		handled = false
	}

	if !handled {
		if v.session.handler == nil {
			return v.programError("This is a bug? Did not process '" + command.Original() + "'")
		}
		ok, err := v.session.handler.Handle(&ExecutionContext{vm: v}, command, args)
		if err != nil {
			return v.programError(err.Error())
		}
		if !ok {
			return v.programError("This is a bug? Did not process '" + command.Original() + "'")
		}
	}
	return v.runHooks(v.session.after[command.Name()], command, args)
}

func (v *vm) Resolve(name string) (string, error) {
	if value, ok := v.locals[name]; ok {
		return value, nil
	}
	value, ok := v.session.env[name]
	if !ok {
		return "", fmt.Errorf("Variable %s is not set", name)
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("Variable %s is not a string", name)
	}
	return text, nil
}

func (v *vm) shift(name string) (string, bool, error) {
	value, err := v.Resolve(name)
	if err != nil {
		return "", false, err
	}
	items := splitList(value)
	if len(items) == 0 {
		return "", false, nil
	}
	first := items[0]
	remaining := strings.Join(items[1:], ", ")
	if _, local := v.locals[name]; local {
		v.locals[name] = remaining
	} else {
		v.session.env[name] = remaining
	}
	return first, true, nil
}

func (v *vm) runHooks(hooks []hook, command *Command, args []string) error {
	if v.session.hookDepth != 0 || len(hooks) == 0 {
		return nil
	}
	for _, h := range hooks {
		if !h.applies(v) {
			continue
		}
		locals := positionalLocals(args)
		if command != nil {
			full, err := command.FullCommand(v)
			if err != nil {
				return v.programError(err.Error())
			}
			locals["%_"] = full
		} else {
			locals["%_"] = ""
		}
		if top := v.peek(); top != nil {
			locals["%type"] = top.Type()
		} else {
			locals["%type"] = ""
		}
		locals["%file"] = filepath.Base(v.spec.file)
		locals["%target"] = v.target
		child := *v
		child.locals = locals
		v.session.hookDepth++
		commands := []*Command{h.action}
		index := 0
		err := child.runCommand(commands, &index)
		v.session.hookDepth--
		if err != nil {
			return err
		}
	}
	return nil
}

func (h hook) applies(v *vm) bool {
	if h.typeName != "" {
		top := v.peek()
		if top == nil || top.Type() != h.typeName {
			return false
		}
	}
	if h.file != "" && h.file != filepath.Base(v.spec.file) {
		return false
	}
	return h.label == "" || h.label == v.target
}

func makeHook(args []string, action *Command) hook {
	h := hook{command: args[0], action: action}
	filters := args[1 : len(args)-1]
	if len(filters) > 0 {
		h.typeName = filters[0]
	}
	if len(filters) > 1 {
		h.file = filters[1]
	}
	if len(filters) > 2 {
		h.label = filters[2]
	}
	return h
}

func (v *vm) push(value StackValue) {
	if value.Object == nil {
		value.Data = append([]byte(nil), value.Data...)
	}
	v.session.stack = append(v.session.stack, value)
	v.lastArgument = nil
}

func (v *vm) pop() (StackValue, error) {
	if len(v.session.stack) == 0 {
		return StackValue{}, v.programError("POP - stack is empty")
	}
	index := len(v.session.stack) - 1
	value := v.session.stack[index]
	v.session.stack = v.session.stack[:index]
	v.lastArgument = &value
	return value, nil
}

func (v *vm) popBytes() (StackValue, error) {
	value, err := v.pop()
	if err != nil {
		return StackValue{}, err
	}
	if value.Object != nil {
		return StackValue{}, v.programError("POP expected BYTES, received " + value.Type())
	}
	return value, nil
}

func (v *vm) peek() *StackValue {
	if len(v.session.stack) == 0 {
		return nil
	}
	return &v.session.stack[len(v.session.stack)-1]
}

func (v *vm) resolveInputFile(argument string) (string, error) {
	path := argument
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(v.spec.file), path)
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", v.programError("File does not exist " + path)
		}
		return "", v.programError(err.Error())
	}
	if info.IsDir() {
		return "", v.programError("File is a folder " + path)
	}
	return path, nil
}

func (v *vm) log(kind MessageType, text string) {
	if v.session.logger != nil {
		v.session.logger.LogSpecMessage(Message{Type: kind, Text: text, File: filepath.Base(v.spec.file), Target: v.target})
	}
}

// ProgramError contains execution context compatible with upstream diagnostics.
type ProgramError struct {
	Message      string
	File         string
	Target       string
	LastCommand  string
	Variables    map[string]string
	LastArgument *StackValue
	Stack        []StackValue
}

func (e *ProgramError) Error() string {
	var result strings.Builder
	fmt.Fprintf(&result, "%s in %s (%s)\n", e.Message, filepath.Base(e.File), e.Target)
	fmt.Fprintf(&result, "Last command:  %s\n", e.LastCommand)
	if len(e.Variables) != 0 {
		fmt.Fprintf(&result, "Variables:     %v\n", e.Variables)
	}
	if e.LastArgument == nil {
		result.WriteString("Last argument: [null]\n")
	} else {
		fmt.Fprintf(&result, "Last argument: %s as %s\n", e.LastArgument.Source, e.LastArgument.Type())
	}
	fmt.Fprintf(&result, "Stack:         %v\n", e.Stack)
	return result.String()
}

func (v *vm) programError(message string) *ProgramError {
	return &ProgramError{Message: message, File: v.spec.file, Target: v.target, LastCommand: v.lastCommand, Variables: cloneStrings(v.lastVariables), LastArgument: v.lastArgument, Stack: append([]StackValue(nil), v.session.stack...)}
}

func positionalLocals(args []string) map[string]string {
	locals := make(map[string]string, len(args))
	for index, value := range args {
		locals[fmt.Sprintf("%%%d", index+1)] = value
	}
	return locals
}

func splitList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	return parts
}

func cloneStrings(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func setMetadata(metadata *Metadata, key, value string) {
	switch key {
	case "author":
		metadata.Author = value
	case "describe":
		metadata.Description = value
	case "license":
		metadata.License = value
	case "name":
		metadata.Name = value
	case "reference":
		metadata.Reference = value
	}
}
