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

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var chartPath = "testdata/testcharts/subchart"

func TestTemplateCmd(t *testing.T) {
	deletevalchart := "testdata/testcharts/issue-9027"

	tests := []cmdTestCase{
		{
			name:   "check name",
			cmd:    fmt.Sprintf("template '%s'", chartPath),
			golden: "output/template.txt",
		},
		{
			name:   "check set name",
			cmd:    fmt.Sprintf("template '%s' --set service.name=apache", chartPath),
			golden: "output/template-set.txt",
		},
		{
			name:   "check values files",
			cmd:    fmt.Sprintf("template '%s' --values '%s'", chartPath, filepath.Join(chartPath, "charts", "subchartA", "values.yaml")),
			golden: "output/template-values-files.txt",
		},
		{
			name:   "check name template",
			cmd:    fmt.Sprintf(`template '%s' --name-template='foobar-{{ b64enc "abc" | lower }}-baz'`, chartPath),
			golden: "output/template-name-template.txt",
		},
		{
			name:      "check no args",
			cmd:       "template",
			wantError: true,
			golden:    "output/template-no-args.txt",
		},
		{
			name:      "check library chart",
			cmd:       fmt.Sprintf("template '%s'", "testdata/testcharts/lib-chart"),
			wantError: true,
			golden:    "output/template-lib-chart.txt",
		},
		{
			name:      "check chart bad type",
			cmd:       fmt.Sprintf("template '%s'", "testdata/testcharts/chart-bad-type"),
			wantError: true,
			golden:    "output/template-chart-bad-type.txt",
		},
		{
			name:   "check chart with dependency which is an app chart acting as a library chart",
			cmd:    fmt.Sprintf("template '%s'", "testdata/testcharts/chart-with-template-lib-dep"),
			golden: "output/template-chart-with-template-lib-dep.txt",
		},
		{
			name:   "check chart with dependency which is an app chart archive acting as a library chart",
			cmd:    fmt.Sprintf("template '%s'", "testdata/testcharts/chart-with-template-lib-archive-dep"),
			golden: "output/template-chart-with-template-lib-archive-dep.txt",
		},
		{
			name:   "check kube version",
			cmd:    fmt.Sprintf("template --kube-version 1.16.0 '%s'", chartPath),
			golden: "output/template-with-kube-version.txt",
		},
		{
			name:   "check kube api versions",
			cmd:    fmt.Sprintf("template --api-versions helm.k8s.io/test,helm.k8s.io/test2 '%s'", chartPath),
			golden: "output/template-with-api-version.txt",
		},
		{
			name:   "check kube api versions",
			cmd:    fmt.Sprintf("template --api-versions helm.k8s.io/test --api-versions helm.k8s.io/test2 '%s'", chartPath),
			golden: "output/template-with-api-version.txt",
		},
		{
			name:   "template with CRDs",
			cmd:    fmt.Sprintf("template '%s' --include-crds", chartPath),
			golden: "output/template-with-crds.txt",
		},
		{
			name:   "template with show-only one",
			cmd:    fmt.Sprintf("template '%s' --show-only templates/service.yaml", chartPath),
			golden: "output/template-show-only-one.txt",
		},
		{
			name:   "template with show-only multiple",
			cmd:    fmt.Sprintf("template '%s' --show-only templates/service.yaml --show-only charts/subcharta/templates/service.yaml", chartPath),
			golden: "output/template-show-only-multiple.txt",
		},
		{
			name:   "template with show-only glob",
			cmd:    fmt.Sprintf("template '%s' --show-only templates/subdir/role*", chartPath),
			golden: "output/template-show-only-glob.txt",
			// Repeat to ensure manifest ordering regressions are caught
			repeat: 10,
		},
		{
			name:   "sorted output of manifests (order of filenames, then order of objects within each YAML file)",
			cmd:    fmt.Sprintf("template '%s'", "testdata/testcharts/object-order"),
			golden: "output/object-order.txt",
			// Helm previously used random file order. Repeat the test so we
			// don't accidentally get the expected result.
			repeat: 10,
		},
		{
			name:      "chart with template with invalid yaml",
			cmd:       fmt.Sprintf("template '%s'", "testdata/testcharts/chart-with-template-with-invalid-yaml"),
			wantError: true,
			golden:    "output/template-with-invalid-yaml.txt",
		},
		{
			name:      "chart with template with invalid yaml (--debug)",
			cmd:       fmt.Sprintf("template '%s' --debug", "testdata/testcharts/chart-with-template-with-invalid-yaml"),
			wantError: true,
			golden:    "output/template-with-invalid-yaml-debug.txt",
		},
		{
			name:      "chart with template with invalid template expression (--debug, --show-only)",
			cmd:       fmt.Sprintf("template '%s' --debug --show-only %s", "testdata/testcharts/chart-with-template-with-invalid-template-expr", "templates/alpine-pod.yaml"),
			wantError: true,
			golden:    "output/template-with-invalid-template-expr-debug-show-only.txt",
		},
		{
			name:   "template skip-tests",
			cmd:    fmt.Sprintf(`template '%s' --skip-tests`, chartPath),
			golden: "output/template-skip-tests.txt",
		},
		{
			// This test case is to ensure the case where specified dependencies
			// in the Chart.yaml and those where the Chart.yaml don't have them
			// specified are the same.
			name:   "ensure nil/null values pass to subcharts delete values",
			cmd:    fmt.Sprintf("template '%s'", deletevalchart),
			golden: "output/issue-9027.txt",
		},
		{
			// Ensure that parent chart values take precedence over imported values
			name:   "template with imported subchart values ensuring import",
			cmd:    fmt.Sprintf("template '%s' --set configmap.enabled=true --set subchartb.enabled=true", chartPath),
			golden: "output/template-subchart-cm.txt",
		},
		{
			// Ensure that user input values take precedence over imported
			// values from sub-charts.
			name:   "template with imported subchart values set with --set",
			cmd:    fmt.Sprintf("template '%s' --set configmap.enabled=true --set subchartb.enabled=true --set configmap.value=baz", chartPath),
			golden: "output/template-subchart-cm-set.txt",
		},
		{
			// Ensure that user input values take precedence over imported
			// values from sub-charts when passed by file
			name:   "template with imported subchart values set with --set",
			cmd:    fmt.Sprintf("template '%s' -f %s/extra_values.yaml", chartPath, chartPath),
			golden: "output/template-subchart-cm-set-file.txt",
		},
	}
	runTestCmd(t, tests)
}

func TestTemplateRenderTimeoutFlagValidation(t *testing.T) {
	cases := []string{
		"--render-timeout=0s",
		"--render-timeout=-1s",
		"--render-timeout=soon",
		"--render-timeout=12",
	}
	for _, flag := range cases {
		_, _, err := executeActionCommandC(storageFixture(), fmt.Sprintf("template %s '%s'", flag, chartPath))
		require.Error(t, err, "expected %s to be rejected", flag)
		assert.Contains(t, err.Error(), "invalid render timeout")
	}

	// A positive duration is accepted and does not change rendering output.
	_, out, err := executeActionCommandC(storageFixture(), fmt.Sprintf("template '%s' --render-timeout=1h", chartPath))
	require.NoError(t, err)
	assert.Contains(t, out, "# Source:")
}

func TestTemplateRenderPartialResults(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: partial\nversion: 0.1.0\n"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "templates"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "templates", "zz-good.yaml"),
		[]byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: render-good\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "templates", "yy-bad.yaml"),
		[]byte(`{{ fail "planned partial failure" }}`), 0o600))

	// Without partial products a render failure keeps the historical
	// behavior: the command fails and no manifest is printed.
	_, out, err := executeActionCommandC(storageFixture(), fmt.Sprintf("template '%s'", dir))
	require.Error(t, err)
	assert.NotContains(t, out, "render-good")

	// With partial products the command is still reported as failed and the
	// complete failure list is returned, but the successful template is
	// printed while the failed one stays absent.
	_, partialOut, partialErr := executeActionCommandC(storageFixture(), fmt.Sprintf("template '%s' --render-partial", dir))
	require.Error(t, partialErr)
	assert.Contains(t, partialErr.Error(), "planned partial failure")
	assert.Contains(t, partialOut, "name: render-good")
	// The failure is reported (its path appears in the error text), but no
	// product is emitted for the failed template.
	assert.NotContains(t, partialOut, "# Source: partial/templates/yy-bad.yaml")
	assert.Contains(t, partialOut, "execution error at (partial/templates/yy-bad.yaml")
}

func TestTemplateVersionCompletion(t *testing.T) {
	repoFile := "testdata/helmhome/helm/repositories.yaml"
	repoCache := "testdata/helmhome/helm/repository"

	repoSetup := fmt.Sprintf("--repository-config %s --repository-cache %s", repoFile, repoCache)

	tests := []cmdTestCase{{
		name:   "completion for template version flag with release name",
		cmd:    repoSetup + " __complete template releasename testing/alpine --version ''",
		golden: "output/version-comp.txt",
	}, {
		name:   "completion for template version flag with generate-name",
		cmd:    repoSetup + " __complete template --generate-name testing/alpine --version ''",
		golden: "output/version-comp.txt",
	}, {
		name:   "completion for template version flag too few args",
		cmd:    repoSetup + " __complete template testing/alpine --version ''",
		golden: "output/version-invalid-comp.txt",
	}, {
		name:   "completion for template version flag too many args",
		cmd:    repoSetup + " __complete template releasename testing/alpine badarg --version ''",
		golden: "output/version-invalid-comp.txt",
	}, {
		name:   "completion for template version flag invalid chart",
		cmd:    repoSetup + " __complete template releasename invalid/invalid --version ''",
		golden: "output/version-invalid-comp.txt",
	}}
	runTestCmd(t, tests)
}

func TestTemplateFileCompletion(t *testing.T) {
	checkFileCompletion(t, "template", false)
	checkFileCompletion(t, "template --generate-name", true)
	checkFileCompletion(t, "template myname", true)
	checkFileCompletion(t, "template myname mychart", false)
}
