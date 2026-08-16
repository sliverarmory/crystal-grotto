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
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	invalidJSONMessage  = "Bad Request: Invalid JSON"
	bodyTooLargeMessage = "Request body too large"
)

var errBodyTooLarge = errors.New("request body is too large")

type successResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	OutputB64 string `json:"output_b64"`
	Yara      string `json:"yara"`
}

type errorResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Context string `json:"context"`
}

func (s *Sidecar) handleLink(writer http.ResponseWriter, request *http.Request) {
	if !strings.EqualFold(request.Method, http.MethodPost) {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	object, err := readJSONObject(writer, request, s.maxBodyBytes)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeText(writer, http.StatusRequestEntityTooLarge, bodyTooLargeMessage)
			return
		}
		writeText(writer, http.StatusBadRequest, invalidJSONMessage)
		return
	}

	writeJSON(writer, http.StatusOK, s.process(request.Context(), object))
}

// handleDie preserves Crystal Palace's opt-in shutdown contract: every HTTP
// method receives an empty 200 response, followed by server shutdown after a
// 200ms grace period. The library never terminates its host process directly;
// ListenAndServe returns cleanly so a standalone CLI exits naturally.
func (s *Sidecar) handleDie(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusOK)
	s.dieOnce.Do(func() {
		go func() {
			timer := time.NewTimer(upstreamDieDelay)
			defer timer.Stop()
			<-timer.C
			close(s.die)
		}()
	})
}

func readJSONObject(writer http.ResponseWriter, request *http.Request, limit int64) (map[string]json.RawMessage, error) {
	body := http.MaxBytesReader(writer, request.Body, limit)
	defer body.Close()

	decoder := json.NewDecoder(body)
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return nil, errBodyTooLarge
		}
		return nil, err
	}

	var trailing json.RawMessage
	err := decoder.Decode(&trailing)
	if err == nil {
		return nil, errors.New("multiple JSON values")
	}
	if !errors.Is(err, io.EOF) {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return nil, errBodyTooLarge
		}
		return nil, err
	}

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("JSON value is not an object")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil || object == nil {
		return nil, errors.New("JSON value is not an object")
	}
	return object, nil
}

func (s *Sidecar) process(ctx context.Context, object map[string]json.RawMessage) any {
	stage := "Init"
	action, err := requiredString(object, "action")
	if err != nil {
		return applicationError(stage, err)
	}
	params, err := requiredObject(object, "params")
	if err != nil {
		return applicationError(stage, err)
	}

	var file, arch string
	switch action {
	case "link":
		stage = "params.file"
		file, err = requiredString(params, "file")
		if err != nil {
			return applicationError(stage, err)
		}
	case "build", "piclink":
		// Crystal Palace leaves this context at Init while reading params.arch.
		stage = "Init"
		arch, err = requiredString(params, "arch")
		if err != nil {
			return applicationError(stage, err)
		}
	default:
		return applicationError("Init", fmt.Errorf("Unknown action: %s", action))
	}

	stage = "params.spec"
	specPath, err := requiredString(params, "spec")
	if err != nil {
		return applicationError(stage, err)
	}

	stage = "env"
	environment, err := parseEnvironment(object["env"])
	if err != nil {
		var envError *environmentError
		if errors.As(err, &envError) {
			stage = "env." + envError.key
		}
		return applicationError(stage, err)
	}

	stage = "config"
	configs, err := parseConfigs(object["config"])
	if err != nil {
		return applicationError(stage, err)
	}
	yara := optionalBoolean(object["yara"])

	stage = action
	var result Result
	if action == "link" {
		result, err = s.linker.Link(ctx, LinkRequest{
			Spec:        specPath,
			File:        file,
			Config:      configs,
			Environment: environment,
			Yara:        yara,
		})
	} else {
		result, err = s.linker.Build(ctx, BuildRequest{
			Spec:        specPath,
			Arch:        arch,
			Config:      configs,
			Environment: environment,
			Yara:        yara,
		})
	}
	if err != nil {
		var contextual interface{ SidecarContext() string }
		if errors.As(err, &contextual) && contextual.SidecarContext() != "" {
			stage = contextual.SidecarContext()
		}
		return applicationError(stage, err)
	}

	return successResponse{
		Success:   true,
		Message:   result.Message,
		OutputB64: base64.StdEncoding.EncodeToString(result.Output),
		Yara:      string(result.Yara),
	}
}

func requiredString(object map[string]json.RawMessage, key string) (string, error) {
	raw, ok := object[key]
	if !ok {
		return "", fmt.Errorf("JSONObject[%q] not found.", key)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("JSONObject[%q] is not a string.", key)
	}
	return value, nil
}

func requiredObject(object map[string]json.RawMessage, key string) (map[string]json.RawMessage, error) {
	raw, ok := object[key]
	if !ok {
		return nil, fmt.Errorf("JSONObject[%q] not found.", key)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("JSONObject[%q] is not a JSONObject.", key)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &result); err != nil || result == nil {
		return nil, fmt.Errorf("JSONObject[%q] is not a JSONObject.", key)
	}
	return result, nil
}

func parseEnvironment(raw json.RawMessage) (Environment, error) {
	environment := make(Environment)
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return environment, nil
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil || object == nil {
		return environment, nil
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value, err := requiredString(object, key)
		if err != nil {
			return nil, &environmentError{key: key, err: err}
		}
		switch {
		case strings.HasPrefix(key, "$"):
			decoded, decodeErr := decodeHex(value)
			if decodeErr != nil {
				return nil, &environmentError{key: key, err: decodeErr}
			}
			environment[key] = decoded
		case strings.HasPrefix(key, "%"):
			environment[key] = value
		default:
			return nil, &environmentError{key: key, err: errors.New("Invalid key sigil")}
		}
	}
	return environment, nil
}

func decodeHex(value string) ([]byte, error) {
	compact := strings.ReplaceAll(value, " ", "")
	if len(compact)%2 != 0 {
		return nil, errors.New("NumberFormatException: String length not divisible by 2")
	}
	decoded := make([]byte, len(compact)/2)
	for index := range decoded {
		pair := compact[index*2 : index*2+2]
		value, err := strconv.ParseInt(pair, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("NumberFormatException: For input string: %q under radix 16", pair)
		}
		decoded[index] = byte(value)
	}
	return decoded, nil
}

type environmentError struct {
	key string
	err error
}

func (e *environmentError) Error() string { return e.err.Error() }
func (e *environmentError) Unwrap() error { return e.err }

func parseConfigs(raw json.RawMessage) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, nil
	}
	var values []json.RawMessage
	if err := json.Unmarshal(trimmed, &values); err != nil {
		return nil, nil
	}
	configs := make([]string, 0, len(values))
	for index, value := range values {
		var path string
		if err := json.Unmarshal(value, &path); err != nil {
			return nil, fmt.Errorf("configuration path at index %d is not a string", index)
		}
		configs = append(configs, path)
	}
	return configs, nil
}

func optionalBoolean(raw json.RawMessage) bool {
	var boolean bool
	if json.Unmarshal(raw, &boolean) == nil {
		return boolean
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.EqualFold(text, "true")
	}
	return false
}

func applicationError(stage string, err error) errorResponse {
	return errorResponse{Success: false, Message: err.Error(), Context: stage}
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		writeText(writer, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Content-Length", strconv.Itoa(len(data)))
	writer.WriteHeader(status)
	_, _ = writer.Write(data)
}

func writeText(writer http.ResponseWriter, status int, value string) {
	data := []byte(value)
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Content-Length", strconv.Itoa(len(data)))
	writer.WriteHeader(status)
	_, _ = writer.Write(data)
}
