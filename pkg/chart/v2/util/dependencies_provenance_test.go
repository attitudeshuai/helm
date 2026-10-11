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

package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonutil "helm.sh/helm/v4/pkg/chart/common/util"
	chart "helm.sh/helm/v4/pkg/chart/v2"
)

func findImportRecord(rep *commonutil.Report, path string) *commonutil.ValueRecord {
	for _, sec := range [][]commonutil.ValueRecord{rep.Merged, rep.Replaced, rep.Removed} {
		for i := range sec {
			if sec[i].Path == path {
				return &sec[i]
			}
		}
	}
	return nil
}

func TestProcessDependenciesWithProvenanceImports(t *testing.T) {
	child := &chart.Chart{
		Metadata: &chart.Metadata{Name: "child"},
		Values: map[string]any{
			"exports": map[string]any{
				"data": map[string]any{
					"imported": "hello",
					// Also exported where the parent chart defines its own
					// value of the same name.
					"kept": "imported-kept",
				},
			},
			"myexp": map[string]any{"k": "v"},
		},
	}
	parent := &chart.Chart{
		Metadata: &chart.Metadata{
			Name: "parent",
			Dependencies: []*chart.Dependency{
				{
					Name: "child",
					ImportValues: []any{
						"data",
						map[string]any{"child": "myexp", "parent": "targeted"},
					},
				},
			},
		},
		// Parent chart value takes precedence over the imported value.
		Values: map[string]any{
			"kept": "parent",
		},
	}
	parent.AddDependency(child)

	tr := commonutil.NewTracker()
	require.NoError(t, ProcessDependenciesWithProvenance(parent, map[string]any{}, tr))

	out, err := commonutil.CoalesceValuesWithProvenance(parent, map[string]any{}, tr)
	require.NoError(t, err)

	assert.Equal(t, "hello", out["imported"])
	assert.Equal(t, "v", out["targeted"].(map[string]any)["k"])
	assert.Equal(t, "parent", out["kept"])

	rep := tr.Report()

	// String-form import (child.exports.data -> parent root).
	imp := findImportRecord(rep, "imported")
	require.NotNil(t, imp)
	assert.Equal(t, commonutil.SourceImport, imp.Final.Category)
	assert.Contains(t, imp.Final.Location, "parent/Chart.yaml")
	require.Len(t, imp.Sources, 2)
	assert.Equal(t, commonutil.SourceChartDefault, imp.Sources[0].Category)

	// Map-form import at the targeted parent path.
	targeted := findImportRecord(rep, "targeted.k")
	require.NotNil(t, targeted)
	assert.Equal(t, commonutil.SourceImport, targeted.Final.Category)

	// Parent default overrides the imported value: chain keeps the import.
	kept := findImportRecord(rep, "kept")
	require.NotNil(t, kept)
	assert.Equal(t, commonutil.SourceChartDefault, kept.Final.Category)
	require.Len(t, kept.Sources, 2)
	assert.Equal(t, commonutil.SourceImport, kept.Sources[0].Category)
}
