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

	"helm.sh/helm/v4/pkg/chart/common"
	chart "helm.sh/helm/v4/pkg/chart/v2"
)

const userFileLocation = "user-values.yaml"

func newUserTracker(vals map[string]any) *Tracker {
	t := NewTracker()
	if vals != nil {
		t.SetRoot(t.ShadowForMap(vals, ValueSource{Category: SourceValuesFile, Location: userFileLocation}))
	}
	return t
}

func trackedCoalesce(t *testing.T, c *chart.Chart, vals map[string]any) (*Tracker, common.Values) {
	tr := newUserTracker(vals)
	out, err := CoalesceValuesWithProvenance(c, vals, tr)
	require.NoError(t, err)
	return tr, out
}

func findRecord(rep *Report, path string) *ValueRecord {
	for i := range rep.Merged {
		if rep.Merged[i].Path == path {
			return &rep.Merged[i]
		}
	}
	for i := range rep.Replaced {
		if rep.Replaced[i].Path == path {
			return &rep.Replaced[i]
		}
	}
	for i := range rep.Removed {
		if rep.Removed[i].Path == path {
			return &rep.Removed[i]
		}
	}
	return nil
}

func findConflict(rep *Report, path string) *TypeConflict {
	for i := range rep.Conflicts {
		if rep.Conflicts[i].Path == path {
			return &rep.Conflicts[i]
		}
	}
	return nil
}

func TestProvenanceDefaultsOverridesAndSections(t *testing.T) {
	c := &chart.Chart{
		Metadata: &chart.Metadata{Name: "root"},
		Values: map[string]any{
			"replicas": 1,
			"image": map[string]any{
				"repo": "nginx",
				"tag":  "latest",
			},
			"arr": []any{1, 2},
		},
	}
	vals := map[string]any{
		"replicas": 3,
		"image":    map[string]any{"tag": "1.21"},
		"arr":      []any{9},
		"extra":    "x",
	}

	tr, out := trackedCoalesce(t, c, vals)

	// Values themselves are unchanged.
	assert.Equal(t, 3, out["replicas"])
	assert.Equal(t, map[string]any{"repo": "nginx", "tag": "1.21"}, out["image"])
	assert.Equal(t, []any{9}, out["arr"])
	assert.Equal(t, "x", out["extra"])

	rep := tr.Report()

	// Scalar override: replaced section with full chain (default -> file).
	repRec := findRecord(rep, "replicas")
	require.NotNil(t, repRec)
	assert.True(t, repRec.Replaced)
	require.Len(t, repRec.Sources, 2)
	assert.Equal(t, SourceChartDefault, repRec.Sources[0].Category)
	assert.Equal(t, "root/values.yaml", repRec.Sources[0].Location)
	assert.Equal(t, SourceValuesFile, repRec.Final.Category)

	// Default-only leaf inside a deep-merged table.
	repoRec := findRecord(rep, "image.repo")
	require.NotNil(t, repoRec)
	assert.False(t, repoRec.Replaced)
	assert.Equal(t, SourceChartDefault, repoRec.Final.Category)
	assert.Equal(t, "nginx", repoRec.Value)

	// Table merge leaf override.
	tagRec := findRecord(rep, "image.tag")
	require.NotNil(t, tagRec)
	assert.True(t, tagRec.Replaced)
	assert.Equal(t, "1.21", tagRec.Value)
	assert.Equal(t, SourceValuesFile, tagRec.Final.Category)
	require.Len(t, tagRec.Sources, 2)

	// Arrays are wholesale replaced.
	arrRec := findRecord(rep, "arr")
	require.NotNil(t, arrRec)
	assert.True(t, arrRec.Replaced)

	// User-only value arrives through table merge.
	extraRec := findRecord(rep, "extra")
	require.NotNil(t, extraRec)
	assert.False(t, extraRec.Replaced)
	assert.Equal(t, SourceValuesFile, extraRec.Final.Category)
}

func TestProvenanceNullRemovals(t *testing.T) {
	c := &chart.Chart{
		Metadata: &chart.Metadata{Name: "root"},
		Values: map[string]any{
			"delme":  1,
			"nested": map[string]any{"a": 1},
		},
	}
	vals := map[string]any{
		"delme":  nil,
		"nested": nil,
	}

	tr, out := trackedCoalesce(t, c, vals)
	_, ok := out["delme"]
	assert.False(t, ok)
	_, ok = out["nested"]
	assert.False(t, ok)

	rep := tr.Report()
	del := findRecord(rep, "delme")
	require.NotNil(t, del)
	assert.True(t, del.Deleted)
	require.Len(t, del.Sources, 2)
	assert.Equal(t, SourceChartDefault, del.Sources[0].Category)
	assert.Equal(t, SourceValuesFile, del.Final.Category)

	nested := findRecord(rep, "nested")
	require.NotNil(t, nested)
	assert.True(t, nested.Deleted)
	assert.Equal(t, SourceValuesFile, nested.Final.Category)

	// Leaves of a nullified default table are recorded individually as well.
	nestedA := findRecord(rep, "nested.a")
	require.NotNil(t, nestedA)
	assert.True(t, nestedA.Deleted)
	require.Len(t, nestedA.Sources, 2)
	assert.Equal(t, SourceChartDefault, nestedA.Sources[0].Category)
	assert.Equal(t, SourceValuesFile, nestedA.Final.Category)
}

func TestProvenanceSubchartsGlobalsAndParentOverrides(t *testing.T) {
	sub := &chart.Chart{
		Metadata: &chart.Metadata{Name: "sub"},
		Values: map[string]any{
			"a":      "subdefault",
			"b":      "subb",
			"global": map[string]any{"own": "sg"},
		},
	}
	other := &chart.Chart{
		Metadata: &chart.Metadata{Name: "other"},
		Values: map[string]any{"a": "otherdefault"},
	}
	parent := &chart.Chart{
		Metadata: &chart.Metadata{Name: "parent"},
		Values: map[string]any{
			"global": map[string]any{"g": "parent-global-default"},
			"sub":    map[string]any{"a": "from-parent"},
		},
	}
	parent.AddDependency(sub, other)

	vals := map[string]any{
		"sub":    map[string]any{"b": "fileb"},
		"global": map[string]any{"g": "fileg"},
	}

	tr, out := trackedCoalesce(t, parent, vals)

	subVals := out["sub"].(map[string]any)
	assert.Equal(t, "from-parent", subVals["a"])
	assert.Equal(t, "fileb", subVals["b"])
	assert.Equal(t, "fileg", subVals["global"].(map[string]any)["g"])
	assert.Equal(t, "sg", subVals["global"].(map[string]any)["own"])
	assert.Equal(t, "otherdefault", out["other"].(map[string]any)["a"])

	rep := tr.Report()

	// Parent chart values.yaml overriding the subchart default.
	aRec := findRecord(rep, "sub.a")
	require.NotNil(t, aRec)
	assert.True(t, aRec.Replaced)
	assert.Equal(t, SourceParentOverride, aRec.Final.Category)
	assert.Equal(t, "parent/values.yaml", aRec.Final.Location)
	require.Len(t, aRec.Sources, 2)
	assert.Equal(t, SourceChartDefault, aRec.Sources[0].Category)

	// File-supplied subchart value keeps its file category.
	bRec := findRecord(rep, "sub.b")
	require.NotNil(t, bRec)
	assert.Equal(t, SourceValuesFile, bRec.Final.Category)

	// Global propagated from parent scope.
	gRec := findRecord(rep, "sub.global.g")
	require.NotNil(t, gRec)
	assert.Equal(t, SourceGlobal, gRec.Final.Category)
	assert.Equal(t, userFileLocation, gRec.Final.Location)

	// Subchart own global default.
	ownRec := findRecord(rep, "sub.global.own")
	require.NotNil(t, ownRec)
	assert.Equal(t, SourceChartDefault, ownRec.Final.Category)

	// Same key in a sibling subchart does not collide.
	otherRec := findRecord(rep, "other.a")
	require.NotNil(t, otherRec)
	assert.Equal(t, SourceChartDefault, otherRec.Final.Category)
}

func TestProvenanceTypeConflicts(t *testing.T) {
	c := &chart.Chart{
		Metadata: &chart.Metadata{Name: "root"},
		Values: map[string]any{
			"port": "8080",
			"svc":  map[string]any{"deep": 1},
		},
	}
	vals := map[string]any{
		"port": 8080,
		"svc":  "nope",
	}

	tr, out := trackedCoalesce(t, c, vals)
	assert.Equal(t, 8080, out["port"])
	assert.Equal(t, "nope", out["svc"])

	rep := tr.Report()
	conf := findConflict(rep, "port")
	require.NotNil(t, conf)
	assert.Equal(t, "int", conf.KeptType)
	assert.Equal(t, "string", conf.DroppedType)
	assert.Equal(t, SourceValuesFile, conf.Kept.Category)
	assert.Equal(t, SourceChartDefault, conf.Dropped.Category)

	svcConf := findConflict(rep, "svc")
	require.NotNil(t, svcConf)
	assert.Equal(t, "string", svcConf.KeptType)
	assert.Equal(t, "table", svcConf.DroppedType)
}

func TestProvenanceUnchangedWhenNotRequested(t *testing.T) {
	c := &chart.Chart{
		Metadata: &chart.Metadata{Name: "root"},
		Values:   map[string]any{"a": 1, "t": map[string]any{"k": "v"}},
	}
	vals := map[string]any{"a": 2, "t": map[string]any{"x": "y"}, "gone": nil}

	got, err := CoalesceValues(c, vals)
	require.NoError(t, err)

	tr := newUserTracker(map[string]any{
		"a": 2, "t": map[string]any{"x": "y"}, "gone": nil,
	})
	tracked, err := CoalesceValuesWithProvenance(c, map[string]any{
		"a": 2, "t": map[string]any{"x": "y"}, "gone": nil,
	}, tr)
	require.NoError(t, err)

	assert.Equal(t, got, tracked)
}

func TestProvenanceEmptyReportString(t *testing.T) {
	assert.Empty(t, NewTracker().Report().String())
}
