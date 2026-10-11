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

package values

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"helm.sh/helm/v4/pkg/chart/common/util"
	"helm.sh/helm/v4/pkg/getter"
)

// mockGetter implements getter.Getter for testing
type mockGetter struct {
	content []byte
	err     error
}

func (m *mockGetter) Get(_ string, _ ...getter.Option) (*bytes.Buffer, error) {
	if m.err != nil {
		return nil, m.err
	}
	return bytes.NewBuffer(m.content), nil
}

// mockProvider creates a test provider
func mockProvider(schemes []string, content []byte, err error) getter.Provider {
	return getter.Provider{
		Schemes: schemes,
		New: func(_ ...getter.Option) (getter.Getter, error) {
			return &mockGetter{content: content, err: err}, nil
		},
	}
}

func TestReadFile(t *testing.T) {
	tests := []struct {
		name         string
		filePath     string
		providers    getter.Providers
		setupFunc    func(*testing.T) (string, func()) // setup temp files, return cleanup
		expectError  bool
		expectStdin  bool
		expectedData []byte
	}{
		{
			name:        "stdin input with dash",
			filePath:    "-",
			providers:   getter.Providers{},
			expectStdin: true,
			expectError: false,
		},
		{
			name:        "stdin input with whitespace",
			filePath:    "  -  ",
			providers:   getter.Providers{},
			expectStdin: true,
			expectError: false,
		},
		{
			name:        "invalid URL parsing",
			filePath:    "://invalid-url",
			providers:   getter.Providers{},
			expectError: true,
		},
		{
			name:      "local file - existing",
			filePath:  "test.txt",
			providers: getter.Providers{},
			setupFunc: func(t *testing.T) (string, func()) {
				t.Helper()
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "test.txt")
				content := []byte("local file content")
				require.NoError(t, os.WriteFile(filePath, content, 0o644))
				return filePath, func() {} // cleanup handled by t.TempDir()
			},
			expectError:  false,
			expectedData: []byte("local file content"),
		},
		{
			name:        "local file - non-existent",
			filePath:    "/non/existent/file.txt",
			providers:   getter.Providers{},
			expectError: true,
		},
		{
			name:     "remote file with http scheme - success",
			filePath: "http://example.com/values.yaml",
			providers: getter.Providers{
				mockProvider([]string{"http", "https"}, []byte("remote content"), nil),
			},
			expectError:  false,
			expectedData: []byte("remote content"),
		},
		{
			name:     "remote file with https scheme - success",
			filePath: "https://example.com/values.yaml",
			providers: getter.Providers{
				mockProvider([]string{"http", "https"}, []byte("https content"), nil),
			},
			expectError:  false,
			expectedData: []byte("https content"),
		},
		{
			name:     "remote file with custom scheme - success",
			filePath: "oci://registry.example.com/chart",
			providers: getter.Providers{
				mockProvider([]string{"oci"}, []byte("oci content"), nil),
			},
			expectError:  false,
			expectedData: []byte("oci content"),
		},
		{
			name:     "remote file - getter error",
			filePath: "http://example.com/values.yaml",
			providers: getter.Providers{
				mockProvider([]string{"http"}, nil, errors.New("network error")),
			},
			expectError: true,
		},
		{
			name:     "unsupported scheme fallback to local file",
			filePath: "ftp://example.com/file.txt",
			providers: getter.Providers{
				mockProvider([]string{"http"}, []byte("should not be used"), nil),
			},
			setupFunc: func(t *testing.T) (string, func()) {
				t.Helper()
				// Create a local file named "ftp://example.com/file.txt"
				// This tests the fallback behavior when scheme is not supported
				tmpDir := t.TempDir()
				fileName := "ftp_file.txt" // Valid filename for filesystem
				filePath := filepath.Join(tmpDir, fileName)
				content := []byte("local fallback content")
				require.NoError(t, os.WriteFile(filePath, content, 0o644))
				return filePath, func() {}
			},
			expectError:  false,
			expectedData: []byte("local fallback content"),
		},
		{
			name:        "empty file path",
			filePath:    "",
			providers:   getter.Providers{},
			expectError: true, // Empty path should cause error
		},
		{
			name:     "multiple providers - correct selection",
			filePath: "custom://example.com/resource",
			providers: getter.Providers{
				mockProvider([]string{"http", "https"}, []byte("wrong content"), nil),
				mockProvider([]string{"custom"}, []byte("correct content"), nil),
				mockProvider([]string{"oci"}, []byte("also wrong"), nil),
			},
			expectError:  false,
			expectedData: []byte("correct content"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actualFilePath string
			var cleanup func()

			if tt.setupFunc != nil {
				actualFilePath, cleanup = tt.setupFunc(t)
				defer cleanup()
			} else {
				actualFilePath = tt.filePath
			}

			// Handle stdin test case
			if tt.expectStdin {
				// Save original stdin
				originalStdin := os.Stdin
				defer func() { os.Stdin = originalStdin }()

				// Create a pipe for stdin
				r, w, err := os.Pipe()
				require.NoError(t, err)
				defer r.Close()
				defer w.Close()

				// Replace stdin with our pipe
				os.Stdin = r

				// Write test data to stdin
				testData := []byte("stdin test data")
				go func() {
					defer w.Close()
					w.Write(testData)
				}()

				// Test the function
				got, err := readFile(actualFilePath, tt.providers)
				require.NoError(t, err, "readFile() expected no error for stdin")
				assert.Equal(t, testData, got)
			} else {
				// Regular test cases
				got, err := readFile(actualFilePath, tt.providers)
				if tt.expectError {
					assert.Error(t, err)
				} else {
					require.NoError(t, err)
					if tt.expectedData != nil {
						assert.Equal(t, tt.expectedData, got)
					}
				}
			}
		})
	}
}

// TestReadFileErrorMessages tests specific error scenarios and their messages
func TestReadFileErrorMessages(t *testing.T) {
	tests := []struct {
		name      string
		filePath  string
		providers getter.Providers
		wantErr   string
	}{
		{
			name:      "URL parse error",
			filePath:  "://invalid",
			providers: getter.Providers{},
			wantErr:   "missing protocol scheme",
		},
		{
			name:      "getter error with message",
			filePath:  "http://example.com/file",
			providers: getter.Providers{mockProvider([]string{"http"}, nil, errors.New("connection refused"))},
			wantErr:   "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readFile(tt.filePath, tt.providers)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// Original test case - keeping for backward compatibility
func TestReadFileOriginal(t *testing.T) {
	var p getter.Providers
	filePath := "%a.txt"
	_, err := readFile(filePath, p)
	assert.Error(t, err, "Expected error when has special strings")
}

func TestMergeValuesCLI(t *testing.T) {
	tests := []struct {
		name     string
		opts     Options
		expected map[string]any
		wantErr  bool
	}{
		{
			name: "set-json object",
			opts: Options{
				JSONValues: []string{`{"foo": {"bar": "baz"}}`},
			},
			expected: map[string]any{
				"foo": map[string]any{
					"bar": "baz",
				},
			},
		},
		{
			name: "set-json key=value",
			opts: Options{
				JSONValues: []string{"foo.bar=[1,2,3]"},
			},
			expected: map[string]any{
				"foo": map[string]any{
					"bar": []any{1.0, 2.0, 3.0},
				},
			},
		},
		{
			name: "set regular value",
			opts: Options{
				Values: []string{"foo=bar"},
			},
			expected: map[string]any{
				"foo": "bar",
			},
		},
		{
			name: "set string value",
			opts: Options{
				StringValues: []string{"foo=123"},
			},
			expected: map[string]any{
				"foo": "123",
			},
		},
		{
			name: "set literal value",
			opts: Options{
				LiteralValues: []string{"foo=true"},
			},
			expected: map[string]any{
				"foo": "true",
			},
		},
		{
			name: "multiple options",
			opts: Options{
				Values:        []string{"a=foo"},
				StringValues:  []string{"b=bar"},
				JSONValues:    []string{`{"c": "foo1"}`},
				LiteralValues: []string{"d=bar1"},
			},
			expected: map[string]any{
				"a": "foo",
				"b": "bar",
				"c": "foo1",
				"d": "bar1",
			},
		},
		{
			name: "invalid json",
			opts: Options{
				JSONValues: []string{`{invalid`},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.opts.MergeValues(getter.Providers{})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
		})
	}
}

func findOptionRecord(rep *util.Report, path string) *util.ValueRecord {
	sections := [][]util.ValueRecord{rep.Merged, rep.Replaced, rep.Removed}
	for _, sec := range sections {
		for i := range sec {
			if sec[i].Path == path {
				return &sec[i]
			}
		}
	}
	return nil
}

func TestMergeValuesWithProvenance(t *testing.T) {
	tmpDir := t.TempDir()
	valuesFile := filepath.Join(tmpDir, "vals.yaml")
	require.NoError(t, os.WriteFile(valuesFile, []byte("a: fromfile\nover: fileval\nnested:\n  x: 1\n"), 0o644))

	opts := Options{
		ValueFiles:   []string{valuesFile},
		Values:       []string{"over=setval", "setonly=1"},
		StringValues: []string{"str=007"},
		JSONValues:   []string{`{"j":"v"}`},
	}

	// Tracked values must equal the untracked merge exactly.
	expected, err := opts.MergeValues(getter.Providers{})
	require.NoError(t, err)

	tr := util.NewTracker()
	got, err := opts.MergeValuesWithProvenance(getter.Providers{}, tr)
	require.NoError(t, err)
	assert.Equal(t, expected, got)

	rep := tr.Report()

	a := findOptionRecord(rep, "a")
	require.NotNil(t, a)
	assert.Equal(t, util.SourceValuesFile, a.Final.Category)
	assert.Equal(t, valuesFile, a.Final.Location)

	// File value overridden by --set: full chain in the replaced section.
	over := findOptionRecord(rep, "over")
	require.NotNil(t, over)
	assert.True(t, over.Replaced)
	require.Len(t, over.Sources, 2)
	assert.Equal(t, util.SourceValuesFile, over.Sources[0].Category)
	assert.Equal(t, util.SourceSet, over.Final.Category)
	assert.Contains(t, over.Final.Location, "--set[0]")

	nested := findOptionRecord(rep, "nested.x")
	require.NotNil(t, nested)
	assert.False(t, nested.Replaced)
	assert.Equal(t, util.SourceValuesFile, nested.Final.Category)

	setonly := findOptionRecord(rep, "setonly")
	require.NotNil(t, setonly)
	assert.Equal(t, util.SourceSet, setonly.Final.Category)
	assert.Contains(t, setonly.Final.Location, "--set[1]")

	str := findOptionRecord(rep, "str")
	require.NotNil(t, str)
	assert.Equal(t, util.SourceSetString, str.Final.Category)

	j := findOptionRecord(rep, "j")
	require.NotNil(t, j)
	assert.Equal(t, util.SourceSetJSON, j.Final.Category)
}

func TestMergeValuesWithProvenanceSetFile(t *testing.T) {
	tmpDir := t.TempDir()
	dataFile := filepath.Join(tmpDir, "payload.txt")
	require.NoError(t, os.WriteFile(dataFile, []byte("payload"), 0o644))

	opts := Options{FileValues: []string{"key=" + filepath.ToSlash(dataFile)}}
	tr := util.NewTracker()
	got, err := opts.MergeValuesWithProvenance(getter.Providers{}, tr)
	require.NoError(t, err)
	assert.Equal(t, "payload", got["key"])

	rep := tr.Report()
	rec := findOptionRecord(rep, "key")
	require.NotNil(t, rec)
	assert.Equal(t, util.SourceSetFile, rec.Final.Category)
	assert.Contains(t, rec.Final.Location, "--set-file[0]")
}

