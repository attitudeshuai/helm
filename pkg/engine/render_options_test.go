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
	"context"
	"errors"
	"path"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"

	"helm.sh/helm/v4/pkg/chart/common"
	chart "helm.sh/helm/v4/pkg/chart/v2"
)

func TestParseRenderTimeout(t *testing.T) {
	cases := []struct {
		input   string
		want    *time.Duration
		wantErr bool
	}{
		{input: "", want: nil},
		{input: "   ", want: nil},
		{input: "1s", want: durationPtr(time.Second)},
		{input: "250ms", want: durationPtr(250 * time.Millisecond)},
		{input: "1m30s", want: durationPtr(90 * time.Second)},
		{input: "0", wantErr: true},
		{input: "0s", wantErr: true},
		{input: "-1s", wantErr: true},
		{input: "soon", wantErr: true},
		{input: "12", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseRenderTimeout(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRenderOptions_Validate(t *testing.T) {
	require.NoError(t, RenderOptions{}.Validate())
	require.NoError(t, RenderOptions{Timeout: durationPtr(time.Second), PartialResults: true}.Validate())
	require.Error(t, RenderOptions{Timeout: durationPtr(0)}.Validate())
	require.Error(t, RenderOptions{Timeout: durationPtr(-time.Second)}.Validate())
}

func durationPtr(d time.Duration) *time.Duration {
	return &d
}

func renderTestChart(t *testing.T, templates map[string]string, deps ...*chart.Chart) *chart.Chart {
	t.Helper()
	modTime := time.Now()
	c := &chart.Chart{
		Metadata: &chart.Metadata{Name: "moby", Version: "1.2.3"},
		Values:   map[string]any{},
	}
	for name, data := range templates {
		c.Templates = append(c.Templates, &common.File{
			Name: path.Join("templates", name), ModTime: modTime, Data: []byte(data),
		})
	}
	for _, dep := range deps {
		c.AddDependency(dep)
	}
	return c
}

func renderTestValues() common.Values {
	return common.Values{"Values": map[string]any{}}
}

// With the zero RenderOptions the result and error must be identical to the
// legacy RenderWithContext path, both on success and on failure.
func TestRenderWithOptions_LegacyIdentity(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := renderTestChart(t, map[string]string{
			"good.yaml": "good: value",
		})
		vals := renderTestValues()

		legacy, legacyErr := new(Engine).RenderWithContext(t.Context(), c, vals)
		result, err := new(Engine).RenderWithOptions(t.Context(), c, vals, RenderOptions{})
		require.Equal(t, legacyErr, err)
		require.NoError(t, err)
		assert.Equal(t, legacy, result.Files)
		assert.Empty(t, result.Failures)
	})

	t.Run("parse error text", func(t *testing.T) {
		c := renderTestChart(t, map[string]string{
			"broken.yaml": `{{ .Values.Missing `,
		})
		vals := renderTestValues()

		_, legacyErr := new(Engine).RenderWithContext(t.Context(), c, vals)
		result, err := new(Engine).RenderWithOptions(t.Context(), c, vals, RenderOptions{})
		require.Error(t, err)
		require.Error(t, legacyErr)
		assert.Equal(t, legacyErr.Error(), err.Error())
		assert.Empty(t, result.Files)
	})

	t.Run("execution error text", func(t *testing.T) {
		c := renderTestChart(t, map[string]string{
			"broken.yaml": `{{ fail "boom" }}`,
		})
		vals := renderTestValues()

		_, legacyErr := new(Engine).RenderWithContext(t.Context(), c, vals)
		_, err := new(Engine).RenderWithOptions(t.Context(), c, vals, RenderOptions{})
		require.Error(t, err)
		require.Error(t, legacyErr)
		assert.Equal(t, legacyErr.Error(), err.Error())
	})
}

func TestRenderWithOptions_InvalidTimeoutRejected(t *testing.T) {
	c := renderTestChart(t, map[string]string{"good.yaml": "good: value"})
	for _, timeout := range []time.Duration{0, -time.Second, -time.Minute} {
		_, err := new(Engine).RenderWithOptions(t.Context(), c, renderTestValues(), RenderOptions{Timeout: &timeout})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid render timeout")
	}
}

func TestRenderWithOptions_CollectsAllExecutionFailures(t *testing.T) {
	c := renderTestChart(t, map[string]string{
		"_helpers.tpl": `{{- define "moby.helper" -}}shaken{{- end -}}`,
		"zz-good.yaml": "good: {{ include \"moby.helper\" . }}",
		"yy-bad1.yaml": `{{ fail "failure one" }}`,
		"xx-bad2.yaml": `{{ required "failure two" "" }}`,
	})
	vals := renderTestValues()

	t.Run("partial products kept with complete failure list", func(t *testing.T) {
		result, err := new(Engine).RenderWithOptions(t.Context(), c, vals, RenderOptions{PartialResults: true})
		require.Error(t, err)
		var renderErr *RenderError
		require.True(t, errors.As(err, &renderErr))

		assert.Equal(t, map[string]string{"moby/templates/zz-good.yaml": "good: shaken"}, result.Files)

		byPath := failuresByPath(result.Failures)
		require.Contains(t, byPath, "moby/templates/yy-bad1.yaml")
		require.Contains(t, byPath, "moby/templates/xx-bad2.yaml")
		for _, f := range result.Failures {
			assert.Equal(t, RenderStageExecute, f.Stage)
			assert.False(t, f.TimedOut)
		}
		assert.Contains(t, byPath["moby/templates/yy-bad1.yaml"].Error(), "failure one")
		assert.Contains(t, byPath["moby/templates/xx-bad2.yaml"].Error(), "failure two")
		// Partials never show up as direct products.
		for name := range result.Files {
			assert.Falsef(t, strings.HasPrefix(path.Base(name), "_"), "partial template %q must not be returned directly", name)
		}
		// The aggregated error lists every failure, not only the first one.
		assert.Contains(t, err.Error(), "failure one")
		assert.Contains(t, err.Error(), "failure two")
	})

	t.Run("overall failure still discards products by default", func(t *testing.T) {
		// A configured timeout enables the deadline-aware path, but without
		// partial products the historical overall-failure semantics hold:
		// all failures are reported and no products are returned.
		result, err := new(Engine).RenderWithOptions(t.Context(), c, vals, RenderOptions{Timeout: durationPtr(time.Minute)})
		require.Error(t, err)
		assert.Empty(t, result.Files)
		assert.Len(t, result.Failures, 2)
	})
}

func TestRenderWithOptions_CollectsAllParseFailures(t *testing.T) {
	c := renderTestChart(t, map[string]string{
		"zz-good.yaml": "good: value",
		"yy-bad.yaml":  `{{ .Values.Missing `,
		"xx-bad.yaml":  `{{ if }}`,
	})
	vals := renderTestValues()

	result, err := new(Engine).RenderWithOptions(t.Context(), c, vals, RenderOptions{PartialResults: true})
	require.Error(t, err)
	var renderErr *RenderError
	require.True(t, errors.As(err, &renderErr))

	assert.Equal(t, map[string]string{"moby/templates/zz-good.yaml": "good: value"}, result.Files)
	byPath := failuresByPath(result.Failures)
	require.Contains(t, byPath, "moby/templates/yy-bad.yaml")
	require.Contains(t, byPath, "moby/templates/xx-bad.yaml")
	for _, f := range result.Failures {
		assert.Equal(t, RenderStageParse, f.Stage)
		assert.False(t, f.TimedOut)
	}
}

// stallEngine returns an engine with a "stall" template function that blocks
// until release is closed. started is signaled once the stall is entered.
func stallEngine(t *testing.T) (Engine, chan<- struct{}, <-chan struct{}) {
	t.Helper()
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	e := Engine{
		CustomTemplateFuncs: template.FuncMap{
			"stall": func() string {
				started <- struct{}{}
				<-release
				return "late"
			},
		},
	}
	return e, release, started
}

func TestRenderWithOptions_TimeoutKeepsIndependentTemplateStates(t *testing.T) {
	e, release, started := stallEngine(t)
	c := renderTestChart(t, map[string]string{
		// Same path depth executes in reverse lexical order: c, b, a.
		"c-good.yaml":  "good: early",
		"b-stall.yaml": `{{ stall }}`,
		"a-late.yaml":  "good: late",
	})

	timeout := 200 * time.Millisecond
	start := time.Now()
	result, err := e.RenderWithOptions(t.Context(), c, renderTestValues(), RenderOptions{
		Timeout: durationPtr(timeout), PartialResults: true,
	})
	elapsed := time.Since(start)

	require.Error(t, err)
	// The render call stops waiting for the in-flight template promptly.
	assert.Less(t, elapsed, 2*time.Second, "render must not wait indefinitely for the stalled template")
	select {
	case <-started:
	default:
		t.Fatal("stalled template execution was never started")
	}

	// The completed template is kept verbatim; the rest is absent.
	assert.Equal(t, map[string]string{"moby/templates/c-good.yaml": "good: early"}, result.Files)

	byPath := failuresByPath(result.Failures)
	inFlight, ok := byPath["moby/templates/b-stall.yaml"]
	require.True(t, ok)
	assert.Equal(t, RenderStageExecute, inFlight.Stage)
	assert.True(t, inFlight.TimedOut)
	assert.Contains(t, inFlight.Error(), "while executing")

	notStarted, ok := byPath["moby/templates/a-late.yaml"]
	require.True(t, ok)
	assert.Equal(t, RenderStageExecute, notStarted.Stage)
	assert.True(t, notStarted.TimedOut)
	assert.Contains(t, notStarted.Error(), "before template")

	// Let the orphaned execution finish.
	close(release)
}

func TestRenderWithOptions_TimeoutWithoutPartialDiscardsProducts(t *testing.T) {
	e, release, _ := stallEngine(t)
	c := renderTestChart(t, map[string]string{
		"c-good.yaml":  "good: early",
		"b-stall.yaml": `{{ stall }}`,
		"a-late.yaml":  "good: late",
	})

	result, err := e.RenderWithOptions(t.Context(), c, renderTestValues(), RenderOptions{
		Timeout: durationPtr(200 * time.Millisecond),
	})
	require.Error(t, err)
	assert.Empty(t, result.Files)
	assert.Len(t, result.Failures, 2)
	close(release)
}

func TestRenderWithOptions_CallerDeadlineDrivesTimeout(t *testing.T) {
	e, release, started := stallEngine(t)
	c := renderTestChart(t, map[string]string{
		"b-stall.yaml": `{{ stall }}`,
		"a-late.yaml":  "good: late",
	})

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	result, err := e.RenderWithOptions(ctx, c, renderTestValues(), RenderOptions{PartialResults: true})
	require.Error(t, err)
	select {
	case <-started:
	default:
		t.Fatal("stalled template execution was never started")
	}
	assert.Empty(t, result.Files)
	require.Len(t, result.Failures, 2)
	for _, f := range result.Failures {
		assert.True(t, f.TimedOut)
	}
	close(release)
}

func TestRenderWithOptions_CancellationIsMarkedSeparatelyFromTimeout(t *testing.T) {
	e, release, started := stallEngine(t)
	c := renderTestChart(t, map[string]string{
		"stall.yaml": `{{ stall }}`,
	})

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-started
		cancel()
	}()

	result, err := e.RenderWithOptions(ctx, c, renderTestValues(), RenderOptions{PartialResults: true})
	require.Error(t, err)
	require.Len(t, result.Failures, 1)
	f := result.Failures[0]
	assert.Equal(t, RenderStageExecute, f.Stage)
	assert.False(t, f.TimedOut, "a plain cancellation must not be reported as a timeout")
	assert.True(t, errors.Is(f.Reason, context.Canceled))
	assert.Contains(t, f.Error(), "rendering cancelled while executing")
	close(release)
}

func TestRenderWithOptions_DeadlineBeforeParsing(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err := new(Engine).renderWithOptions(ctx, map[string]renderable{
		"a": {tpl: "good: a", vals: renderTestValues()},
		"b": {tpl: "good: b", vals: renderTestValues()},
	}, RenderOptions{PartialResults: true})
	require.Error(t, err)
	assert.Empty(t, result.Files)
	require.Len(t, result.Failures, 2)
	for _, f := range result.Failures {
		assert.Equal(t, RenderStageParse, f.Stage)
		assert.False(t, f.TimedOut)
	}
}

// Nested rendering through 'tpl' is bounded by the same render deadline.
func TestRenderWithOptions_TimeoutCoversNestedTpl(t *testing.T) {
	e, release, started := stallEngine(t)
	c := renderTestChart(t, map[string]string{
		"nested.yaml": `{{ tpl "{{ stall }}" . }}`,
	})

	result, err := e.RenderWithOptions(t.Context(), c, renderTestValues(), RenderOptions{
		Timeout: durationPtr(200 * time.Millisecond), PartialResults: true,
	})
	require.Error(t, err)
	select {
	case <-started:
	default:
		t.Fatal("nested tpl execution was never started")
	}
	assert.Empty(t, result.Files)
	require.Len(t, result.Failures, 1)
	f := result.Failures[0]
	assert.Equal(t, "moby/templates/nested.yaml", f.Path)
	assert.True(t, f.TimedOut)
	close(release)
}

// Subchart templates share the deadline with the parent: a subchart
// template that completes before the deadline is kept, while parent
// templates that run into the deadline are reported as failures.
func TestRenderWithOptions_TimeoutCoversSubcharts(t *testing.T) {
	e, release, started := stallEngine(t)
	sub := renderTestChart(t, map[string]string{"good.yaml": "sub: good"})
	sub.Metadata.Name = "sub"
	c := renderTestChart(t, map[string]string{
		"z-stall.yaml": `{{ stall }}`,
		"a-late.yaml":  "root: late",
	}, sub)
	c.Metadata.Name = "moby"

	result, err := e.RenderWithOptions(t.Context(), c, map[string]any{
		"Values": map[string]any{"sub": map[string]any{}},
	}, RenderOptions{Timeout: durationPtr(200 * time.Millisecond), PartialResults: true})
	require.Error(t, err)
	select {
	case <-started:
	default:
		t.Fatal("stalled template execution was never started")
	}

	assert.Contains(t, result.Files, "moby/charts/sub/templates/good.yaml")
	assert.NotContains(t, result.Files, "moby/templates/z-stall.yaml")
	assert.NotContains(t, result.Files, "moby/templates/a-late.yaml")
	byPath := failuresByPath(result.Failures)
	assert.True(t, byPath["moby/templates/z-stall.yaml"].TimedOut)
	assert.True(t, byPath["moby/templates/a-late.yaml"].TimedOut)
	close(release)
}

// blockingDynamicClient blocks Get until its context is done, then waits
// for release, so the engine's deadline select deterministically wins and
// the test can observe the cancellation signal delivered to the client.
type blockingDynamicClient struct {
	dynamic.NamespaceableResourceInterface
	started   chan struct{}
	sawCancel chan error
	release   chan struct{}
}

func (c *blockingDynamicClient) Namespace(_ string) dynamic.ResourceInterface { return c }

func (c *blockingDynamicClient) Get(ctx context.Context, _ string, _ metav1.GetOptions, _ ...string) (*unstructured.Unstructured, error) {
	c.started <- struct{}{}
	<-ctx.Done()
	c.sawCancel <- ctx.Err()
	<-c.release
	return nil, ctx.Err()
}

type blockingProvider struct {
	client dynamic.NamespaceableResourceInterface
}

func (p *blockingProvider) GetClientFor(_, _ string) (dynamic.NamespaceableResourceInterface, bool, error) {
	return p.client, true, nil
}

func TestRenderWithOptions_LookupReceivesCancellation(t *testing.T) {
	client := &blockingDynamicClient{
		started:   make(chan struct{}, 1),
		sawCancel: make(chan error, 1),
		release:   make(chan struct{}, 1),
	}
	t.Cleanup(func() { client.release <- struct{}{} })

	var provider ClientProvider = &blockingProvider{client: client}
	e := Engine{clientProvider: &provider}

	c := renderTestChart(t, map[string]string{
		"c-good.yaml": "good: early",
		"b-look.yaml": `{{ lookup "v1" "ConfigMap" "ns" "blocked" }}`,
		"a-late.yaml": "good: late",
	})

	result, err := e.RenderWithOptions(t.Context(), c, renderTestValues(), RenderOptions{
		Timeout: durationPtr(200 * time.Millisecond), PartialResults: true,
	})
	require.Error(t, err)

	select {
	case <-client.started:
	default:
		t.Fatal("lookup was never invoked")
	}
	select {
	case cause := <-client.sawCancel:
		assert.True(t, errors.Is(cause, context.DeadlineExceeded), "lookup must receive the deadline cancellation, got %v", cause)
	case <-time.After(2 * time.Second):
		t.Fatal("lookup did not observe the cancelled context")
	}

	assert.Equal(t, map[string]string{"moby/templates/c-good.yaml": "good: early"}, result.Files)
	byPath := failuresByPath(result.Failures)
	require.Contains(t, byPath, "moby/templates/b-look.yaml")
	assert.True(t, byPath["moby/templates/b-look.yaml"].TimedOut)
}

func TestRenderWithOptions_StrictModeStillFailsPerTemplate(t *testing.T) {
	e := Engine{Strict: true}
	c := renderTestChart(t, map[string]string{
		"zz-good.yaml": "good: value",
		"yy-bad.yaml":  `{{ .undefined }}`,
	})
	result, err := e.RenderWithOptions(t.Context(), c, renderTestValues(), RenderOptions{PartialResults: true})
	require.Error(t, err)
	assert.Contains(t, result.Files, "moby/templates/zz-good.yaml")
	byPath := failuresByPath(result.Failures)
	require.Contains(t, byPath, "moby/templates/yy-bad.yaml")
	assert.Equal(t, RenderStageExecute, byPath["moby/templates/yy-bad.yaml"].Stage)
}

func failuresByPath(failures []RenderFailure) map[string]RenderFailure {
	byPath := make(map[string]RenderFailure, len(failures))
	for _, f := range failures {
		byPath[f.Path] = f
	}
	return byPath
}
