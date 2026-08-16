// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

// Package application connects the specification runtime to CLI and sidecar
// transports.
package application

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/engine"
	"github.com/sliverarmory/crystal-grotto/internal/server"
	"github.com/sliverarmory/crystal-grotto/internal/spec"
)

// HandlerFactory creates request-local object/linker command handlers.
type HandlerFactory func() spec.CommandHandler

// Service implements the stateless build and link application boundary.
type Service struct {
	NewHandler HandlerFactory
}

// NewService constructs a service backed by the real Crystal Grotto engine.
// The zero value has the same default; the constructor makes that dependency
// explicit at application boundaries such as the Cobra server command.
func NewService() Service { return Service{NewHandler: engine.Factory} }

// Build executes a build-only specification request.
func (s Service) Build(ctx context.Context, request server.BuildRequest) (server.Result, error) {
	capability, err := spec.None(request.Arch)
	if err != nil {
		return server.Result{}, server.WithContext("Init", err)
	}
	return s.execute(ctx, "build", request.Spec, request.Config, request.Environment, request.Yara, capability)
}

// Link executes a specification against a DLL or COFF input.
func (s Service) Link(ctx context.Context, request server.LinkRequest) (server.Result, error) {
	if err := contextError(ctx); err != nil {
		return server.Result{}, err
	}
	input, err := os.ReadFile(request.File)
	if err != nil {
		return server.Result{}, server.WithContext("params.file", err)
	}
	capability, err := spec.ParseCapability(input)
	if err != nil {
		return server.Result{}, server.WithContext("params.file", err)
	}
	return s.execute(ctx, "link", request.Spec, request.Config, request.Environment, request.Yara, capability)
}

func (s Service) execute(ctx context.Context, action, specPath string, configs []string, environment server.Environment, yara bool, capability spec.Capability) (server.Result, error) {
	if err := contextError(ctx); err != nil {
		return server.Result{}, err
	}
	program, err := parseFile(specPath)
	if err != nil {
		return server.Result{}, server.WithContext("params.spec", err)
	}

	env := copyEnvironment(environment)
	messages := make([]string, 0)
	logger := spec.LoggerFunc(func(message spec.Message) {
		prefix := "[*] "
		if message.Type == spec.MessageWarning {
			prefix = "[!] "
		}
		messages = append(messages, prefix+message.String())
	})
	factory := s.NewHandler
	if factory == nil {
		factory = engine.Factory
	}
	handler := factory()
	options := spec.RunOptions{Environment: env, Logger: logger, Handler: handler}
	for index, configPath := range configs {
		if err := contextError(ctx); err != nil {
			return server.Result{}, err
		}
		config, err := parseFile(configPath)
		stage := fmt.Sprintf("config[%d] (%s)", index, filepath.Base(configPath))
		if err != nil {
			return server.Result{}, server.WithContext(stage, err)
		}
		if _, err := config.RunConfig(capability, options); err != nil {
			return server.Result{}, server.WithContext(stage, err)
		}
	}
	if err := contextError(ctx); err != nil {
		return server.Result{}, err
	}

	result := server.Result{}
	if yara {
		generated, err := program.RunAndGenerate(capability, options)
		if err != nil {
			return server.Result{}, server.WithContext(action, err)
		}
		result.Output = generated.Program
		result.Yara = generated.Rules
		result.Message = strings.Join(messages, "\n")
		return result, nil
	}
	output, err := program.Run(capability, options)
	if err != nil {
		return server.Result{}, server.WithContext(action, err)
	}
	result.Output = output
	result.Message = strings.Join(messages, "\n")
	return result, nil
}

func parseFile(path string) (*spec.Spec, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return spec.Parse(path, string(content))
}

func copyEnvironment(environment server.Environment) spec.Environment {
	result := make(spec.Environment, len(environment))
	for key, value := range environment {
		if data, ok := value.([]byte); ok {
			result[key] = append([]byte(nil), data...)
		} else {
			result[key] = value
		}
	}
	return result
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("request context is nil")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
