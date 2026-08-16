// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type decodedResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Context   string `json:"context"`
	OutputB64 string `json:"output_b64"`
	Yara      string `json:"yara"`
}

func TestLinkRequestAndSuccessResponse(t *testing.T) {
	var captured LinkRequest
	sidecar := mustSidecar(t, LinkerFuncs{
		LinkFunc: func(_ context.Context, request LinkRequest) (Result, error) {
			captured = request
			return Result{
				Message: "[!] warning\n[*] information",
				Output:  []byte{0, 1, 2},
				Yara:    []byte("rule crystal_grotto {}"),
			}, nil
		},
	}, Config{})

	body := `{
        "action":"link",
        "params":{"file":"module.x64.o","spec":"loader.spec"},
        "env":{"$KEY":"00 11aA","$SIGNED":"-1 +1","%name":"grotto"},
        "config":["first.spec","second.spec"],
        "yara":true,
        "ignored":"value"
    }`
	response := performRequest(sidecar, http.MethodPost, "/link", body)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got, want := response.Header().Get("Content-Length"), strconv.Itoa(response.Body.Len()); got != want {
		t.Fatalf("Content-Length = %q, want %q", got, want)
	}

	decoded := decodeResponse(t, response)
	assertJSONKeys(t, response.Body.Bytes(), "success", "message", "output_b64", "yara")
	if !decoded.Success {
		t.Fatalf("response unexpectedly failed: %+v", decoded)
	}
	if decoded.Message != "[!] warning\n[*] information" {
		t.Fatalf("message = %q", decoded.Message)
	}
	output, err := base64.StdEncoding.DecodeString(decoded.OutputB64)
	if err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if !bytes.Equal(output, []byte{0, 1, 2}) {
		t.Fatalf("output = %x", output)
	}
	if decoded.Yara != "rule crystal_grotto {}" {
		t.Fatalf("yara = %q", decoded.Yara)
	}

	if captured.Spec != "loader.spec" || captured.File != "module.x64.o" || !captured.Yara {
		t.Fatalf("captured request = %+v", captured)
	}
	if want := []string{"first.spec", "second.spec"}; !reflect.DeepEqual(captured.Config, want) {
		t.Fatalf("config = %#v, want %#v", captured.Config, want)
	}
	if got, ok := captured.Environment["$KEY"].([]byte); !ok || !bytes.Equal(got, []byte{0, 0x11, 0xaa}) {
		t.Fatalf("$KEY = %#v", captured.Environment["$KEY"])
	}
	if got, ok := captured.Environment["$SIGNED"].([]byte); !ok || !bytes.Equal(got, []byte{0xff, 0x01}) {
		t.Fatalf("$SIGNED = %#v", captured.Environment["$SIGNED"])
	}
	if got := captured.Environment["%name"]; got != "grotto" {
		t.Fatalf("%%name = %#v", got)
	}
}

func TestBuildRequestDefaultsAndStringBoolean(t *testing.T) {
	var captured BuildRequest
	sidecar := mustSidecar(t, LinkerFuncs{
		BuildFunc: func(_ context.Context, request BuildRequest) (Result, error) {
			captured = request
			return Result{}, nil
		},
	}, Config{})

	response := performRequest(sidecar, "post", "/link", `{
        "action":"build",
        "params":{"spec":"program.spec","arch":"named.x64"},
        "env":"ignored like upstream",
        "config":{"also":"ignored"},
        "yara":"TRUE"
    }`)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if decoded := decodeResponse(t, response); !decoded.Success {
		t.Fatalf("response unexpectedly failed: %+v", decoded)
	}
	if captured.Spec != "program.spec" || captured.Arch != "named.x64" || !captured.Yara {
		t.Fatalf("captured request = %+v", captured)
	}
	if len(captured.Config) != 0 || len(captured.Environment) != 0 {
		t.Fatalf("optional defaults = config %#v env %#v", captured.Config, captured.Environment)
	}
}

func TestLegacyPiclinkUsesBuildContract(t *testing.T) {
	t.Parallel()
	var captured BuildRequest
	sidecar := mustSidecar(t, LinkerFuncs{
		BuildFunc: func(_ context.Context, request BuildRequest) (Result, error) {
			captured = request
			return Result{Output: []byte{0x42}}, nil
		},
	}, Config{})
	response := performRequest(sidecar, http.MethodPost, "/link", `{"action":"piclink","params":{"spec":"program.spec","arch":"x86"}}`)
	decoded := decodeResponse(t, response)
	if !decoded.Success || captured.Spec != "program.spec" || captured.Arch != "x86" {
		t.Fatalf("response=%+v request=%+v", decoded, captured)
	}
}

func TestOptionalBooleanMatchesJSONObjectCoercion(t *testing.T) {
	tests := []struct {
		json string
		want bool
	}{
		{json: "true", want: true},
		{json: "false", want: false},
		{json: `"TrUe"`, want: true},
		{json: `"FALSE"`, want: false},
		{json: `"t"`, want: false},
		{json: `"1"`, want: false},
		{json: "1", want: false},
		{json: "null", want: false},
		{json: "", want: false},
	}
	for _, test := range tests {
		if got := optionalBoolean(json.RawMessage(test.json)); got != test.want {
			t.Errorf("optionalBoolean(%q) = %v, want %v", test.json, got, test.want)
		}
	}
}

func TestApplicationValidationErrorsRemainHTTP200(t *testing.T) {
	sidecar := mustSidecar(t, successfulLinker(), Config{})
	tests := []struct {
		name    string
		body    string
		context string
		message string
	}{
		{name: "missing action", body: `{}`, context: "Init", message: `JSONObject["action"] not found.`},
		{name: "action wrong type", body: `{"action":7,"params":{}}`, context: "Init", message: `JSONObject["action"] is not a string.`},
		{name: "missing params", body: `{"action":"link"}`, context: "Init", message: `JSONObject["params"] not found.`},
		{name: "params wrong type", body: `{"action":"link","params":"x"}`, context: "Init", message: `JSONObject["params"] is not a JSONObject.`},
		{name: "unknown action", body: `{"action":"launch","params":{}}`, context: "Init", message: "Unknown action: launch"},
		{name: "missing link file", body: `{"action":"link","params":{"spec":"x"}}`, context: "params.file", message: `JSONObject["file"] not found.`},
		{name: "missing build arch", body: `{"action":"build","params":{"spec":"x"}}`, context: "Init", message: `JSONObject["arch"] not found.`},
		{name: "missing spec", body: `{"action":"link","params":{"file":"x"}}`, context: "params.spec", message: `JSONObject["spec"] not found.`},
		{name: "invalid env sigil", body: `{"action":"build","params":{"arch":"x64","spec":"x"},"env":{"NAME":"value"}}`, context: "env.NAME", message: "Invalid key sigil"},
		{name: "odd hex", body: `{"action":"build","params":{"arch":"x64","spec":"x"},"env":{"$KEY":"abc"}}`, context: "env.$KEY", message: "NumberFormatException: String length not divisible by 2"},
		{name: "invalid hex", body: `{"action":"build","params":{"arch":"x64","spec":"x"},"env":{"$KEY":"zz"}}`, context: "env.$KEY", message: `NumberFormatException: For input string: "zz" under radix 16`},
		{name: "env value wrong type", body: `{"action":"build","params":{"arch":"x64","spec":"x"},"env":{"%name":3}}`, context: "env.%name", message: `JSONObject["%name"] is not a string.`},
		{name: "config value wrong type", body: `{"action":"build","params":{"arch":"x64","spec":"x"},"config":["ok.spec",3]}`, context: "config", message: "configuration path at index 1 is not a string"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performRequest(sidecar, http.MethodPost, "/link", test.body)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", response.Code, response.Body.String())
			}
			decoded := decodeResponse(t, response)
			assertJSONKeys(t, response.Body.Bytes(), "success", "message", "context")
			if decoded.Success || decoded.Context != test.context || decoded.Message != test.message {
				t.Fatalf("response = %+v, want context=%q message=%q", decoded, test.context, test.message)
			}
			if decoded.OutputB64 != "" || decoded.Yara != "" {
				t.Fatalf("error response leaked success fields: %+v", decoded)
			}
		})
	}
}

func TestLinkerErrorsRemainHTTP200AndCanOverrideContext(t *testing.T) {
	sidecar := mustSidecar(t, LinkerFuncs{
		BuildFunc: func(context.Context, BuildRequest) (Result, error) {
			return Result{}, WithContext("config[0] (broken.spec)", errors.New("specification failed"))
		},
	}, Config{})

	response := performRequest(sidecar, http.MethodPost, "/link", `{"action":"build","params":{"arch":"x64","spec":"main.spec"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	decoded := decodeResponse(t, response)
	if decoded.Success || decoded.Context != "config[0] (broken.spec)" || decoded.Message != "specification failed" {
		t.Fatalf("response = %+v", decoded)
	}
}

func TestTransportErrorsAndLimits(t *testing.T) {
	var calls atomic.Int32
	sidecar := mustSidecar(t, LinkerFuncs{
		BuildFunc: func(context.Context, BuildRequest) (Result, error) {
			calls.Add(1)
			return Result{}, nil
		},
	}, Config{MaxBodyBytes: 96})

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		response := performRequest(sidecar, method, "/link", `{}`)
		if response.Code != http.StatusMethodNotAllowed || response.Body.Len() != 0 {
			t.Fatalf("%s response = status %d body %q", method, response.Code, response.Body.String())
		}
	}

	for _, body := range []string{"", "{", "[]", "null", `{} {}`} {
		response := performRequest(sidecar, http.MethodPost, "/link", body)
		if response.Code != http.StatusBadRequest || response.Body.String() != invalidJSONMessage {
			t.Fatalf("body %q response = status %d body %q", body, response.Code, response.Body.String())
		}
	}

	oversized := `{"action":"build","params":{"arch":"x64","spec":"` + strings.Repeat("x", 128) + `"}}`
	response := performRequest(sidecar, http.MethodPost, "/link", oversized)
	if response.Code != http.StatusRequestEntityTooLarge || response.Body.String() != bodyTooLargeMessage {
		t.Fatalf("oversized response = status %d body %q", response.Code, response.Body.String())
	}

	response = performRequest(sidecar, http.MethodPost, "/other", `{}`)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown endpoint status = %d", response.Code)
	}
	if calls.Load() != 0 {
		t.Fatalf("linker called %d times for rejected requests", calls.Load())
	}
}

func TestConcurrentRequestsHaveIndependentState(t *testing.T) {
	const requestCount = 32
	ready := make(chan struct{}, requestCount)
	release := make(chan struct{})
	var calls atomic.Int32

	sidecar := mustSidecar(t, LinkerFuncs{
		BuildFunc: func(_ context.Context, request BuildRequest) (Result, error) {
			calls.Add(1)
			ready <- struct{}{}
			<-release
			id, ok := request.Environment["%id"].(string)
			if !ok {
				return Result{}, errors.New("missing request id")
			}
			request.Environment["%mutated"] = id
			return Result{Output: []byte(id)}, nil
		},
	}, Config{})

	type outcome struct {
		id  string
		err error
	}
	outcomes := make(chan outcome, requestCount)
	var wait sync.WaitGroup
	for index := range requestCount {
		id := strconv.Itoa(index)
		wait.Add(1)
		go func() {
			defer wait.Done()
			body := fmt.Sprintf(`{"action":"build","params":{"arch":"x64","spec":"x"},"env":{"%%id":%q}}`, id)
			response := performRequest(sidecar, http.MethodPost, "/link", body)
			var decoded decodedResponse
			if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
				outcomes <- outcome{id: id, err: err}
				return
			}
			output, err := base64.StdEncoding.DecodeString(decoded.OutputB64)
			if err != nil {
				outcomes <- outcome{id: id, err: err}
				return
			}
			if !decoded.Success || string(output) != id {
				err = fmt.Errorf("response success=%v output=%q", decoded.Success, output)
			}
			outcomes <- outcome{id: id, err: err}
		}()
	}

	for index := 0; index < requestCount; index++ {
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			close(release)
			wait.Wait()
			t.Fatal("requests did not execute concurrently")
		}
	}
	close(release)
	wait.Wait()
	close(outcomes)

	for result := range outcomes {
		if result.err != nil {
			t.Errorf("request %s: %v", result.id, result.err)
		}
	}
	if got := calls.Load(); got != requestCount {
		t.Fatalf("calls = %d, want %d", got, requestCount)
	}
}

func TestLoopbackListenerAndGracefulCancellation(t *testing.T) {
	if got, want := loopbackAddress(DefaultPort), "127.0.0.1:60060"; got != want {
		t.Fatalf("loopback address = %q, want %q", got, want)
	}

	sidecar := mustSidecar(t, successfulLinker(), Config{})
	ctx, cancel := context.WithCancel(context.Background())
	listener := newBlockingListener()
	done := make(chan error, 1)
	go func() { done <- sidecar.serve(ctx, listener) }()
	<-listener.accepting
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not stop after cancellation")
	}
}

type blockingListener struct {
	accepting chan struct{}
	closed    chan struct{}
	ready     sync.Once
	close     sync.Once
}

func newBlockingListener() *blockingListener {
	return &blockingListener{accepting: make(chan struct{}), closed: make(chan struct{})}
}

func (l *blockingListener) Accept() (net.Conn, error) {
	l.ready.Do(func() { close(l.accepting) })
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingListener) Close() error {
	l.close.Do(func() { close(l.closed) })
	return nil
}

func (l *blockingListener) Addr() net.Addr { return stringAddress("127.0.0.1:0") }

type stringAddress string

func (address stringAddress) Network() string { return "tcp4" }
func (address stringAddress) String() string  { return string(address) }

func TestConstructionAndListenValidation(t *testing.T) {
	if _, err := New(nil, Config{}); err == nil {
		t.Fatal("New(nil) succeeded")
	}
	if _, err := New(successfulLinker(), Config{MaxBodyBytes: -1}); err == nil {
		t.Fatal("New accepted a negative body limit")
	}

	sidecar := mustSidecar(t, successfulLinker(), Config{})
	if sidecar.maxBodyBytes != DefaultMaxBodyBytes {
		t.Fatalf("default body limit = %d", sidecar.maxBodyBytes)
	}
	if err := sidecar.ListenAndServe(nil, DefaultPort); err == nil {
		t.Fatal("ListenAndServe accepted a nil context")
	}
	if err := sidecar.ListenAndServe(context.Background(), -1); err == nil {
		t.Fatal("ListenAndServe accepted a negative port")
	}
	if err := sidecar.ListenAndServe(context.Background(), 65536); err == nil {
		t.Fatal("ListenAndServe accepted a port above 65535")
	}

	base := errors.New("failure")
	wrapped := WithContext("params.spec", base)
	if !errors.Is(wrapped, base) {
		t.Fatal("WithContext did not preserve the wrapped error")
	}
	var contextual *ContextError
	if !errors.As(wrapped, &contextual) || contextual.SidecarContext() != "params.spec" {
		t.Fatalf("contextual error = %#v", contextual)
	}
	if WithContext("ignored", nil) != nil {
		t.Fatal("WithContext turned nil into an error")
	}
}

func mustSidecar(t *testing.T, linker Linker, config Config) *Sidecar {
	t.Helper()
	sidecar, err := New(linker, config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sidecar
}

func successfulLinker() Linker {
	return LinkerFuncs{
		LinkFunc:  func(context.Context, LinkRequest) (Result, error) { return Result{}, nil },
		BuildFunc: func(context.Context, BuildRequest) (Result, error) { return Result{}, nil },
	}
}

func performRequest(handler http.Handler, method, target, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder) decodedResponse {
	t.Helper()
	var decoded decodedResponse
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response %q: %v", response.Body.String(), err)
	}
	return decoded
}

func assertJSONKeys(t *testing.T, data []byte, expected ...string) {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatalf("decode response keys: %v", err)
	}
	if len(object) != len(expected) {
		t.Fatalf("response keys = %v, want %v", reflect.ValueOf(object).MapKeys(), expected)
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			t.Fatalf("response is missing key %q: %s", key, data)
		}
	}
}
