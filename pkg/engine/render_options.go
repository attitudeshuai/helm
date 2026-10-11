/*
Copyright The Helm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package engine

import (
	"fmt"
	"strings"
	"time"
)

// RenderStage identifies the phase in which a template could not be rendered.
type RenderStage string

const (
	// RenderStageParse indicates that a template could not be parsed.
	RenderStageParse RenderStage = "parse"
	// RenderStageExecute indicates that a template could not be executed.
	RenderStageExecute RenderStage = "execute"
)

// RenderFailure describes a single template that did not finish rendering.
type RenderFailure struct {
	// Path is the chart-scoped path of the template, for example
	// "mychart/templates/configmap.yaml".
	Path string
	// Stage reports whether the template failed while it was parsed or
	// executed.
	Stage RenderStage
	// TimedOut reports whether the failure was caused by the render deadline
	// being reached. It is false for ordinary parse/execution errors and for
	// cancellations that are not deadline driven.
	TimedOut bool
	// Reason is the formatted failure message.
	Reason error
}

// Error implements error.
func (f RenderFailure) Error() string {
	if f.Reason != nil {
		return f.Reason.Error()
	}
	return fmt.Sprintf("template %q failed during %s", f.Path, f.Stage)
}

// RenderResult is the outcome of an options-enabled render call.
type RenderResult struct {
	// Files contains the rendered content keyed by template path for every
	// template that completed successfully. Partials (templates whose base
	// name starts with "_") never appear here, and neither do templates that
	// did not finish rendering. It is always non-nil.
	Files map[string]string
	// Failures lists every template that could not be rendered. It is empty
	// on success.
	Failures []RenderFailure
}

// RenderOptions configures deadline enforcement and partial results for a
// single render call.
//
// The zero value keeps the historical rendering behavior: templates are
// rendered without an engine-declared deadline and any failure discards all
// rendered content.
type RenderOptions struct {
	// Timeout bounds a single render call, covering the parsing and
	// execution of every template of the chart and its subcharts as well as
	// nested rendering through the 'tpl' and 'include' template functions.
	// When the deadline is reached, no further template execution is
	// started and the render call no longer waits for the template that is
	// currently executing.
	//
	// A nil value disables the engine-declared deadline. A deadline carried
	// by the context passed to the render call is still honored. A non-nil
	// value must be positive; zero and negative durations are rejected by
	// Validate.
	Timeout *time.Duration
	// PartialResults, when true, keeps the templates that rendered
	// successfully even when other templates fail or time out. The usable
	// products are returned in RenderResult.Files alongside the complete
	// failure list, and templates that did not finish are absent from the
	// products.
	//
	// It only affects the result of the render call itself; it does not
	// change how callers judge overall success or failure.
	PartialResults bool
}

// Validate checks the render options. A zero or negative Timeout is rejected.
func (o RenderOptions) Validate() error {
	if o.Timeout != nil && *o.Timeout <= 0 {
		return fmt.Errorf("invalid render timeout %q: duration must be greater than zero", *o.Timeout)
	}
	return nil
}

// ParseRenderTimeout parses a timeout duration supplied as a string, for
// example from a command line flag or a configuration value.
//
// An empty (or whitespace-only) string disables the timeout and returns nil.
// Zero durations, negative durations and values that cannot be parsed as a
// duration are rejected with an error, so that invalid configuration fails at
// the parameter parsing stage.
func ParseRenderTimeout(value string) (*time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return nil, fmt.Errorf("invalid render timeout %q: %w", value, err)
	}
	if duration <= 0 {
		return nil, fmt.Errorf("invalid render timeout %q: duration must be greater than zero", value)
	}
	return &duration, nil
}

// RenderError aggregates every template failure collected during one render
// call. Use errors.As to inspect the individual failures.
type RenderError struct {
	Failures []RenderFailure
}

// Error implements error.
func (e *RenderError) Error() string {
	if len(e.Failures) == 1 {
		return e.Failures[0].Error()
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "template rendering failed for %d templates:", len(e.Failures))
	for _, failure := range e.Failures {
		fmt.Fprintf(&builder, "\n  - %s", failure.Error())
	}
	return builder.String()
}
