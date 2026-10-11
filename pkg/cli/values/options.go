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
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"helm.sh/helm/v4/pkg/chart/common/util"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	"helm.sh/helm/v4/pkg/getter"
	"helm.sh/helm/v4/pkg/strvals"
)

// Options captures the different ways to specify values
type Options struct {
	ValueFiles    []string // -f/--values
	StringValues  []string // --set-string
	Values        []string // --set
	FileValues    []string // --set-file
	JSONValues    []string // --set-json
	LiteralValues []string // --set-literal
}

// MergeValues merges values from files specified via -f/--values and directly
// via --set-json, --set, --set-string, or --set-file, marshaling them to YAML
func (opts *Options) MergeValues(p getter.Providers) (map[string]any, error) {
	base := map[string]any{}

	// User specified a values files via -f/--values
	for _, filePath := range opts.ValueFiles {
		raw, err := readFile(filePath, p)
		if err != nil {
			return nil, err
		}
		currentMap, err := loader.LoadValues(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
		}
		// Merge with the previous map
		base = loader.MergeMaps(base, currentMap)
	}

	// User specified a value via --set-json
	for _, value := range opts.JSONValues {
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue != "" && trimmedValue[0] == '{' {
			// If value is JSON object format, parse it as map
			var jsonMap map[string]any
			if err := json.Unmarshal([]byte(trimmedValue), &jsonMap); err != nil {
				return nil, fmt.Errorf("failed parsing --set-json data JSON: %s", value)
			}
			base = loader.MergeMaps(base, jsonMap)
		} else {
			// Otherwise, parse it as key=value format
			if err := strvals.ParseJSON(value, base); err != nil {
				return nil, fmt.Errorf("failed parsing --set-json data %s", value)
			}
		}
	}

	// User specified a value via --set
	for _, value := range opts.Values {
		if err := strvals.ParseInto(value, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set data: %w", err)
		}
	}

	// User specified a value via --set-string
	for _, value := range opts.StringValues {
		if err := strvals.ParseIntoString(value, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set-string data: %w", err)
		}
	}

	// User specified a value via --set-file
	for _, value := range opts.FileValues {
		reader := func(rs []rune) (any, error) {
			bytes, err := readFile(string(rs), p)
			if err != nil {
				return nil, err
			}
			return string(bytes), err
		}
		if err := strvals.ParseIntoFile(value, base, reader); err != nil {
			return nil, fmt.Errorf("failed parsing --set-file data: %w", err)
		}
	}

	// User specified a value via --set-literal
	for _, value := range opts.LiteralValues {
		if err := strvals.ParseLiteralInto(value, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set-literal data: %w", err)
		}
	}

	return base, nil
}

// MergeValuesWithProvenance behaves like MergeValues but records the source
// (file or command line argument) of every supplied leaf on t. The value
// computation itself is unchanged.
func (opts *Options) MergeValuesWithProvenance(p getter.Providers, t *util.Tracker) (map[string]any, error) {
	base := map[string]any{}
	t.SetRoot(t.EmptyShadow())

	// User specified a values files via -f/--values
	for _, filePath := range opts.ValueFiles {
		raw, err := readFile(filePath, p)
		if err != nil {
			return nil, err
		}
		currentMap, err := loader.LoadValues(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
		}
		// Merge with the previous map
		base = loader.MergeMaps(base, currentMap)
		src := util.ValueSource{Category: util.SourceValuesFile, Location: filePath}
		t.SetRoot(t.MergeMapsShadow(t.Root(), t.ShadowForMap(currentMap, src)))
		t.MarkCheckableLocation(checkableLocation(filePath))
	}

	// User specified a value via --set-json
	for i, value := range opts.JSONValues {
		src := util.ValueSource{Category: util.SourceSetJSON, Location: setLocation("set-json", i, value)}
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue != "" && trimmedValue[0] == '{' {
			// If value is JSON object format, parse it as map
			var jsonMap map[string]any
			if err := json.Unmarshal([]byte(trimmedValue), &jsonMap); err != nil {
				return nil, fmt.Errorf("failed parsing --set-json data JSON: %s", value)
			}
			base = loader.MergeMaps(base, jsonMap)
			t.SetRoot(t.MergeMapsShadow(t.Root(), t.ShadowForMap(jsonMap, src)))
		} else {
			// Otherwise, parse it as key=value format
			if err := strvals.ParseJSON(value, base); err != nil {
				return nil, fmt.Errorf("failed parsing --set-json data %s", value)
			}
			// Parse into a fresh map to enumerate the leaves supplied by this
			// argument; the real merge above keeps the exact parsing behavior.
			contrib := map[string]any{}
			if err := strvals.ParseJSON(value, contrib); err == nil {
				t.RecordSetContribution(contrib, src)
			}
		}
	}

	// User specified a value via --set
	for i, value := range opts.Values {
		if err := strvals.ParseInto(value, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set data: %w", err)
		}
		if contrib, err := strvals.Parse(value); err == nil {
			t.RecordSetContribution(contrib, util.ValueSource{
				Category: util.SourceSet, Location: setLocation("set", i, value),
			})
		}
	}

	// User specified a value via --set-string
	for i, value := range opts.StringValues {
		if err := strvals.ParseIntoString(value, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set-string data: %w", err)
		}
		if contrib, err := strvals.ParseString(value); err == nil {
			t.RecordSetContribution(contrib, util.ValueSource{
				Category: util.SourceSetString, Location: setLocation("set-string", i, value),
			})
		}
	}

	// User specified a value via --set-file
	for i, value := range opts.FileValues {
		reader := func(rs []rune) (any, error) {
			b, err := readFile(string(rs), p)
			if err != nil {
				return nil, err
			}
			return string(b), err
		}
		// Memoize file reads so the contribution parse does not hit the disk
		// twice and so referenced local files can be noted for report checks.
		cache := map[string]any{}
		memoReader := func(rs []rune) (any, error) {
			path := string(rs)
			if v, ok := cache[path]; ok {
				return v, nil
			}
			v, err := reader(rs)
			if err != nil {
				return nil, err
			}
			cache[path] = v
			t.MarkCheckableLocation(checkableLocation(path))
			return v, nil
		}
		if err := strvals.ParseIntoFile(value, base, memoReader); err != nil {
			return nil, fmt.Errorf("failed parsing --set-file data: %w", err)
		}
		if contrib, err := strvals.ParseFile(value, memoReader); err == nil {
			t.RecordSetContribution(contrib, util.ValueSource{
				Category: util.SourceSetFile, Location: setLocation("set-file", i, value),
			})
		}
	}

	// User specified a value via --set-literal
	for i, value := range opts.LiteralValues {
		if err := strvals.ParseLiteralInto(value, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set-literal data: %w", err)
		}
		if contrib, err := strvals.ParseLiteral(value); err == nil {
			t.RecordSetContribution(contrib, util.ValueSource{
				Category: util.SourceSetLiteral, Location: setLocation("set-literal", i, value),
			})
		}
	}

	return base, nil
}

// setLocation renders a command line argument location with its index.
func setLocation(flag string, i int, value string) string {
	return fmt.Sprintf("--%s[%d]: %s", flag, i, value)
}

// checkableLocation returns the location when it refers to a local file, and
// the empty string for stdin ("-") and URLs.
func checkableLocation(loc string) string {
	if strings.TrimSpace(loc) == "-" || strings.Contains(loc, "://") {
		return ""
	}
	return loc
}

// readFile load a file from stdin, the local directory, or a remote file with a url.
func readFile(filePath string, p getter.Providers) ([]byte, error) {
	if strings.TrimSpace(filePath) == "-" {
		return io.ReadAll(os.Stdin)
	}
	u, err := url.Parse(filePath)
	if err != nil {
		return nil, err
	}

	// FIXME: maybe someone handle other protocols like ftp.
	g, err := p.ByScheme(u.Scheme)
	if err != nil {
		return os.ReadFile(filePath)
	}
	data, err := g.Get(filePath, getter.WithURL(filePath))
	if err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}
