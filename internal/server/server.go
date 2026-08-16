// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

// Package server implements Crystal Palace's local JSON-over-HTTP sidecar
// contract without coupling the HTTP layer to a particular linker.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultHost is deliberately not configurable. The sidecar has no
	// authentication and must remain local to the host.
	DefaultHost = "127.0.0.1"
	DefaultPort = 60060

	DefaultMaxBodyBytes   int64 = 1 << 20
	DefaultMaxHeaderBytes       = 64 << 10

	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 30 * time.Second
	defaultWriteTimeout      = 5 * time.Minute
	defaultIdleTimeout       = 60 * time.Second
	defaultShutdownTimeout   = 5 * time.Second
	upstreamDieDelay         = 200 * time.Millisecond
)

// Environment contains byte variables ($NAME) and string variables (%name).
// Every request receives its own environment map and byte slices.
type Environment map[string]any

// LinkRequest describes one sidecar link action.
type LinkRequest struct {
	Spec        string
	File        string
	Config      []string
	Environment Environment
	Yara        bool
}

// BuildRequest describes one sidecar build action.
type BuildRequest struct {
	Spec        string
	Arch        string
	Config      []string
	Environment Environment
	Yara        bool
}

// Result is the successful output of a link or build request.
type Result struct {
	Message string
	Output  []byte
	Yara    []byte
}

// Linker is the narrow boundary between the HTTP sidecar and the linker.
// Implementations must permit concurrent calls.
type Linker interface {
	Link(context.Context, LinkRequest) (Result, error)
	Build(context.Context, BuildRequest) (Result, error)
}

// LinkerFuncs adapts function fields to Linker, which keeps handler tests and
// command wiring independent from the concrete linker implementation.
type LinkerFuncs struct {
	LinkFunc  func(context.Context, LinkRequest) (Result, error)
	BuildFunc func(context.Context, BuildRequest) (Result, error)
}

func (f LinkerFuncs) Link(ctx context.Context, request LinkRequest) (Result, error) {
	if f.LinkFunc == nil {
		return Result{}, errors.New("link action is not configured")
	}
	return f.LinkFunc(ctx, request)
}

func (f LinkerFuncs) Build(ctx context.Context, request BuildRequest) (Result, error) {
	if f.BuildFunc == nil {
		return Result{}, errors.New("build action is not configured")
	}
	return f.BuildFunc(ctx, request)
}

// ContextError lets a linker retain Crystal Palace's response context when an
// error occurs while parsing a spec or running a configuration file.
type ContextError struct {
	Context string
	Err     error
}

func (e *ContextError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ContextError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// SidecarContext returns the context value used in an error response.
func (e *ContextError) SidecarContext() string {
	if e == nil {
		return ""
	}
	return e.Context
}

// WithContext associates an error with a Crystal Palace sidecar context.
func WithContext(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &ContextError{Context: stage, Err: err}
}

// Config controls transport-level resource limits and optional compatibility
// behavior. A zero MaxBodyBytes uses DefaultMaxBodyBytes; negative limits are
// rejected. EnableDie exposes Crystal Palace's unauthenticated /die endpoint.
// It is disabled by default because a browser can trigger the endpoint with a
// loopback GET request.
type Config struct {
	MaxBodyBytes int64
	EnableDie    bool
}

// Sidecar is a concurrency-safe HTTP handler. Its Linker is called
// concurrently and must provide its own safety for shared state.
type Sidecar struct {
	linker       Linker
	maxBodyBytes int64
	mux          *http.ServeMux
	die          chan struct{}
	dieOnce      sync.Once
}

// New constructs a sidecar handler.
func New(linker Linker, config Config) (*Sidecar, error) {
	if linker == nil {
		return nil, errors.New("server linker is nil")
	}
	maxBodyBytes := config.MaxBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}
	if maxBodyBytes < 0 {
		return nil, errors.New("server maximum body size cannot be negative")
	}

	sidecar := &Sidecar{linker: linker, maxBodyBytes: maxBodyBytes}
	sidecar.mux = http.NewServeMux()
	sidecar.mux.HandleFunc("/link", sidecar.handleLink)
	if config.EnableDie {
		sidecar.die = make(chan struct{})
	}
	return sidecar, nil
}

// Handler returns the sidecar as an http.Handler.
func (s *Sidecar) Handler() http.Handler { return s }

// ServeHTTP dispatches sidecar endpoints.
func (s *Sidecar) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// com.sun.net.httpserver matches a registered context as a literal path
	// prefix, so upstream's "/die" also handles paths such as "/die/now" and
	// "/die-suffix". Preserve that behavior only when explicitly enabled.
	if s.die != nil && strings.HasPrefix(request.URL.Path, "/die") {
		s.handleDie(writer, request)
		return
	}
	s.mux.ServeHTTP(writer, request)
}

// ListenAndServe binds exclusively to the IPv4 loopback interface. The port
// may be zero for an ephemeral port; normal callers should use DefaultPort.
func (s *Sidecar) ListenAndServe(ctx context.Context, port int) error {
	if ctx == nil {
		return errors.New("server context is nil")
	}
	if port < 0 || port > 65535 {
		return fmt.Errorf("server port %d is outside 0-65535", port)
	}

	listener, err := listenLoopback(port)
	if err != nil {
		return err
	}
	return s.serve(ctx, listener)
}

func listenLoopback(port int) (net.Listener, error) {
	return net.Listen("tcp4", loopbackAddress(port))
}

func loopbackAddress(port int) string {
	return net.JoinHostPort(DefaultHost, strconv.Itoa(port))
}

func (s *Sidecar) serve(ctx context.Context, listener net.Listener) error {
	httpServer := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
		MaxHeaderBytes:    DefaultMaxHeaderBytes,
	}

	stopWatcher := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
		case <-s.die:
		case <-stopWatcher:
			return
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	err := httpServer.Serve(listener)
	close(stopWatcher)
	<-watcherDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
