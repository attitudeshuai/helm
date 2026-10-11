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

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"helm.sh/helm/v4/pkg/helmpath"
)

// provenanceEnvVars lists every environment variable the provenance
// resolution reads directly.
var provenanceEnvVars = []string{
	"HELM_NAMESPACE", "HELM_MAX_HISTORY", "KUBECONFIG", "HELM_KUBECONTEXT",
	"HELM_KUBETOKEN", "HELM_KUBEASUSER", "HELM_KUBEASGROUPS",
	"HELM_KUBEAPISERVER", "HELM_KUBECAFILE", "HELM_KUBETLS_SERVER_NAME",
	"HELM_KUBEINSECURE_SKIP_TLS_VERIFY", "HELM_PLUGINS", "HELM_REGISTRY_CONFIG",
	"HELM_REPOSITORY_CONFIG", "HELM_REPOSITORY_CACHE", "HELM_CONTENT_CACHE",
	"HELM_BURST_LIMIT", "HELM_QPS", "HELM_COLOR", "NO_COLOR", "HELM_DEBUG",
	"HELM_CACHE_HOME", "HELM_CONFIG_HOME", "HELM_DATA_HOME",
	"XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
}

func clearProvenanceEnv(t *testing.T) {
	t.Helper()
	for _, name := range provenanceEnvVars {
		if v, ok := os.LookupEnv(name); ok {
			// t.Setenv snapshots the current value and restores it on cleanup.
			t.Setenv(name, v)
		} else {
			t.Cleanup(func() { os.Unsetenv(name) })
		}
		os.Unsetenv(name)
	}
}

// bareKubeconfig defines a valid kubeconfig whose current context carries no
// namespace, so namespace resolution falls back to the built-in default
// deterministically.
const bareKubeconfig = `apiVersion: v1
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: test
contexts:
- context:
    cluster: test
    user: test-user
  name: test
current-context: test
kind: Config
preferences: {}
users:
- name: test-user
  user:
    token: test-token
`

// newProvenanceSettings builds EnvSettings from the given environment and
// flag arguments. KUBECONFIG defaults to a valid kubeconfig whose current
// context carries no namespace, so namespace resolution is deterministic and
// independent of the machine running the tests.
func newProvenanceSettings(t *testing.T, args string, env map[string]string) (*EnvSettings, *Report) {
	t.Helper()
	clearProvenanceEnv(t)

	if _, ok := env["KUBECONFIG"]; !ok {
		path := filepath.Join(t.TempDir(), "config")
		require.NoError(t, os.WriteFile(path, []byte(bareKubeconfig), 0o600))
		env["KUBECONFIG"] = path
	}
	for k, v := range env {
		t.Setenv(k, v)
	}

	s := New()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	s.AddFlags(fs)
	if args != "" {
		require.NoError(t, fs.Parse(strings.Fields(args)))
	}
	report := s.Provenance()
	return s, report
}

func findSetting(t *testing.T, r *Report, key string) SettingInfo {
	t.Helper()
	for _, info := range r.Settings {
		if info.Key == key {
			return info
		}
	}
	t.Fatalf("setting %q not found in report", key)
	return SettingInfo{}
}

func winningSource(t *testing.T, info SettingInfo) ValueSource {
	t.Helper()
	for _, src := range info.Sources {
		if src.Winning {
			return src
		}
	}
	t.Fatalf("no winning source for %q", info.Key)
	return ValueSource{}
}

func findSourceByLocation(info SettingInfo, location string) (ValueSource, bool) {
	for _, src := range info.Sources {
		if src.Location == location {
			return src, true
		}
	}
	return ValueSource{}, false
}

const provenanceKubeconfig = `apiVersion: v1
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: test
contexts:
- context:
    cluster: test
    user: test-user
    namespace: kubens
  name: test
current-context: test
kind: Config
preferences: {}
users:
- name: test-user
  user:
    token: test-token
`

func writeKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.WriteFile(path, []byte(provenanceKubeconfig), 0o600))
	return path
}

func TestProvenanceDefaults(t *testing.T) {
	s, r := newProvenanceSettings(t, "", map[string]string{})

	defaults := map[string]string{
		"HELM_DEBUG":                        "false",
		"HELM_MAX_HISTORY":                  "10",
		"HELM_BURST_LIMIT":                  "100",
		"HELM_QPS":                          "0.00",
		"HELM_COLOR":                        "auto",
		"HELM_NAMESPACE":                    "default",
		"HELM_KUBEINSECURE_SKIP_TLS_VERIFY": "false",
	}
	for key, value := range defaults {
		info := findSetting(t, r, key)
		assert.Equal(t, value, info.Value, key)
		win := winningSource(t, info)
		assert.Equal(t, SourceDefault, win.Type, key)
		assert.False(t, win.External, key)
		assert.Contains(t, r.Unset, key)
	}

	// The field values are the effective ones.
	assert.Equal(t, 10, s.MaxHistory)
	assert.Equal(t, 100, s.BurstLimit)
	assert.InDelta(t, float32(0), s.QPS, 0.0001)
	assert.Empty(t, r.Conflicts)
	assert.Empty(t, r.Invalid)
}

func TestProvenanceEnvironmentWins(t *testing.T) {
	_, r := newProvenanceSettings(t, "", map[string]string{
		"HELM_BURST_LIMIT": "150",
		"HELM_DEBUG":       "1",
		"HELM_NAMESPACE":   "envns",
	})

	burst := findSetting(t, r, "HELM_BURST_LIMIT")
	assert.Equal(t, "150", burst.Value)
	win := winningSource(t, burst)
	assert.Equal(t, SourceEnv, win.Type)
	assert.Equal(t, "HELM_BURST_LIMIT", win.Location)
	assert.True(t, win.External)
	assert.NotContains(t, r.Unset, "HELM_BURST_LIMIT")

	debug := findSetting(t, r, "HELM_DEBUG")
	assert.Equal(t, "true", debug.Value)
	assert.True(t, winningSource(t, debug).External)

	ns := findSetting(t, r, "HELM_NAMESPACE")
	assert.Equal(t, "envns", ns.Value)
	assert.Equal(t, SourceEnv, winningSource(t, ns).Type)
}

func TestProvenanceFlagOverridesEnvironment(t *testing.T) {
	s, r := newProvenanceSettings(t, "--burst-limit=175 --namespace flagns", map[string]string{
		"HELM_BURST_LIMIT": "200",
		"HELM_NAMESPACE":   "envns",
	})

	assert.Equal(t, 175, s.BurstLimit)
	assert.Equal(t, "flagns", s.Namespace())

	burst := findSetting(t, r, "HELM_BURST_LIMIT")
	assert.Equal(t, "175", burst.Value)
	win := winningSource(t, burst)
	assert.Equal(t, SourceFlag, win.Type)
	assert.Equal(t, "--burst-limit", win.Location)
	assert.False(t, win.External)

	env, ok := findSourceByLocation(burst, "HELM_BURST_LIMIT")
	require.True(t, ok)
	assert.Equal(t, "200", env.Value)
	assert.NotEmpty(t, env.ShadowReason)
	assert.Contains(t, env.ShadowReason, "--burst-limit")

	// Different values from multiple sources are reported as a conflict.
	require.Len(t, r.Conflicts, 2)
	assert.Equal(t, "HELM_BURST_LIMIT", r.Conflicts[0].Key)
	var effectiveCount int
	for _, v := range r.Conflicts[0].Values {
		if v.Effective {
			assert.Equal(t, "175", v.Value)
			effectiveCount++
		}
	}
	assert.Equal(t, 1, effectiveCount)
}

func TestProvenanceSameValueMultipleSourcesIsNotConflict(t *testing.T) {
	_, r := newProvenanceSettings(t, "--debug", map[string]string{
		"HELM_DEBUG": "true",
	})
	debug := findSetting(t, r, "HELM_DEBUG")
	assert.Equal(t, "true", debug.Value)
	assert.Equal(t, SourceFlag, winningSource(t, debug).Type)

	env, ok := findSourceByLocation(debug, "HELM_DEBUG")
	require.True(t, ok)
	assert.Equal(t, "true", env.Value)
	assert.Contains(t, env.ShadowReason, "same value")

	for _, c := range r.Conflicts {
		assert.NotEqual(t, "HELM_DEBUG", c.Key)
	}
}

func TestProvenanceInvalidValuesFallBackAndAreRecorded(t *testing.T) {
	s, r := newProvenanceSettings(t, "", map[string]string{
		"HELM_BURST_LIMIT":                  "not-an-int",
		"HELM_QPS":                          "abc",
		"HELM_DEBUG":                        "maybe",
		"HELM_KUBEINSECURE_SKIP_TLS_VERIFY": "nope",
	})

	// Fallback behavior is preserved when strict mode is off.
	assert.Equal(t, defaultBurstLimit, s.BurstLimit)
	assert.InDelta(t, defaultQPS, s.QPS, 0.0001)
	assert.False(t, s.Debug)
	assert.False(t, s.KubeInsecureSkipTLSVerify)

	// But the report surfaces every malformed value with its source.
	keys := map[string]bool{}
	for _, d := range r.Invalid {
		keys[d.Key] = true
		assert.NotEmpty(t, d.Location)
		assert.NotEmpty(t, d.Reason)
		assert.NotEmpty(t, d.Expected)
		assert.Equal(t, SourceEnv, d.Source)
	}
	for _, key := range []string{"HELM_BURST_LIMIT", "HELM_QPS", "HELM_DEBUG", "HELM_KUBEINSECURE_SKIP_TLS_VERIFY"} {
		assert.True(t, keys[key], "expected diagnostic for %s", key)
		info := findSetting(t, r, key)
		bad, ok := findSourceByLocation(info, key)
		require.True(t, ok, key)
		assert.NotEmpty(t, bad.Invalid, key)
		assert.NotEmpty(t, bad.ShadowReason)
		assert.Equal(t, SourceDefault, winningSource(t, info).Type, key)
	}

	// Validate exposes the same diagnostics for strict mode.
	diags := s.Validate()
	assert.Len(t, diags, len(r.Invalid))
}

func TestProvenanceInvalidValueCoveredByFlagIsStillReported(t *testing.T) {
	_, r := newProvenanceSettings(t, "--burst-limit=200", map[string]string{
		"HELM_BURST_LIMIT": "abc",
	})
	var found bool
	for _, d := range r.Invalid {
		if d.Key == "HELM_BURST_LIMIT" && d.Location == "HELM_BURST_LIMIT" {
			found = true
		}
	}
	assert.True(t, found)
	burst := findSetting(t, r, "HELM_BURST_LIMIT")
	assert.Equal(t, SourceFlag, winningSource(t, burst).Type)
}

func TestProvenanceEmptyValuesAreUnset(t *testing.T) {
	_, r := newProvenanceSettings(t, "", map[string]string{
		"HELM_NAMESPACE": "",
		"HELM_DEBUG":     "",
		"HELM_QPS":       "",
	})
	for _, key := range []string{"HELM_NAMESPACE", "HELM_DEBUG", "HELM_QPS"} {
		info := findSetting(t, r, key)
		_, hasEnv := findSourceByLocation(info, key)
		assert.False(t, hasEnv, "%s: empty environment value must not be a source", key)
		assert.Equal(t, SourceDefault, winningSource(t, info).Type, key)
	}
}

func TestProvenanceBlankPathFallsBack(t *testing.T) {
	s, r := newProvenanceSettings(t, "", map[string]string{
		"HELM_PLUGINS":   "  /  ",
		"HELM_DATA_HOME": filepath.FromSlash("/elsewhere/data"),
	})
	// HELM_PLUGINS blank does not produce an empty path; the path-derived
	// default (now shaped by HELM_DATA_HOME) is used. HELM_DATA_HOME is the
	// Helm specific data directory, so no extra "helm" segment is appended.
	assert.Equal(t, filepath.Join(filepath.FromSlash("/elsewhere/data"), "plugins"), s.PluginsDirectory)

	info := findSetting(t, r, "HELM_PLUGINS")
	_, hasEnv := findSourceByLocation(info, "HELM_PLUGINS")
	assert.False(t, hasEnv)
	win := winningSource(t, info)
	assert.Equal(t, SourcePath, win.Type)
	assert.Equal(t, "HELM_DATA_HOME", win.Location)
	assert.True(t, win.External)

	// A separator-only base path variable is treated as unset too, and the
	// base path reported is the one actually resolved by the path helper.
	cachePath, cacheOrigin := helmpath.CachePathOrigin()
	cache := findSetting(t, r, "HELM_CACHE_HOME")
	assert.Equal(t, cachePath, cache.Value)
	assert.Equal(t, cacheOrigin.Path, cachePath)
}

func TestProvenancePathVariableSources(t *testing.T) {
	t.Run("helm home base", func(t *testing.T) {
		_, r := newProvenanceSettings(t, "", map[string]string{
			"HELM_DATA_HOME": filepath.FromSlash("/custom/data"),
		})
		data := findSetting(t, r, "HELM_DATA_HOME")
		assert.Equal(t, filepath.Join(filepath.FromSlash("/custom/data")), data.Value)
		win := winningSource(t, data)
		assert.Equal(t, SourcePath, win.Type)
		assert.Equal(t, "HELM_DATA_HOME", win.Location)
		assert.True(t, win.External)

		plugins := findSetting(t, r, "HELM_PLUGINS")
		assert.Equal(t, filepath.Join(filepath.FromSlash("/custom/data"), "plugins"), plugins.Value)
		assert.Equal(t, SourcePath, winningSource(t, plugins).Type)
		def, ok := findSourceByLocation(plugins, "default")
		require.True(t, ok)
		assert.NotEmpty(t, def.ShadowReason)
	})

	t.Run("xdg base", func(t *testing.T) {
		_, r := newProvenanceSettings(t, "", map[string]string{
			"XDG_CACHE_HOME": filepath.FromSlash("/xdg/cache"),
		})
		cache := findSetting(t, r, "HELM_CACHE_HOME")
		win := winningSource(t, cache)
		assert.Equal(t, SourcePath, win.Type)
		assert.Equal(t, "XDG_CACHE_HOME", win.Location)
		assert.True(t, win.External)
		assert.Equal(t, filepath.Join(filepath.FromSlash("/xdg/cache"), "helm"), cache.Value)
	})
}

func TestProvenanceNamespaceFromKubeconfigContext(t *testing.T) {
	kubeconfig := writeKubeconfig(t)

	t.Run("context namespace wins when nothing else is set", func(t *testing.T) {
		s, r := newProvenanceSettings(t, "", map[string]string{"KUBECONFIG": kubeconfig})
		assert.Equal(t, "kubens", s.Namespace())
		ns := findSetting(t, r, "HELM_NAMESPACE")
		assert.Equal(t, "kubens", ns.Value)
		win := winningSource(t, ns)
		assert.Equal(t, SourceKubeconfig, win.Type)
		assert.Contains(t, win.Location, "test")
		assert.NotContains(t, r.Unset, "HELM_NAMESPACE")
	})

	t.Run("flag overrides the context namespace and context is listed shadowed", func(t *testing.T) {
		s, r := newProvenanceSettings(t, "--namespace=flagns", map[string]string{"KUBECONFIG": kubeconfig})
		assert.Equal(t, "flagns", s.Namespace())
		ns := findSetting(t, r, "HELM_NAMESPACE")
		assert.Equal(t, "flagns", ns.Value)
		assert.Equal(t, SourceFlag, winningSource(t, ns).Type)
		ctx, ok := findSourceByLocation(ns, `kubeconfig context "test"`)
		require.True(t, ok)
		assert.Equal(t, "kubens", ctx.Value)
		assert.NotEmpty(t, ctx.ShadowReason)
	})
}

func TestProvenanceKubeconfigReadFailureIsIsolated(t *testing.T) {
	// client-go silently ignores a missing kubeconfig, so use an existing but
	// unparseable file to force an actual read failure.
	bad := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.WriteFile(bad, []byte("this is definitely not a kubeconfig: ["), 0o600))

	s, r := newProvenanceSettings(t, "", map[string]string{
		"KUBECONFIG":       bad,
		"HELM_BURST_LIMIT": "150",
	})

	assert.Equal(t, "default", s.Namespace())
	require.Len(t, r.ReadErrors, 1)
	assert.Equal(t, "HELM_NAMESPACE", r.ReadErrors[0].Key)
	assert.Equal(t, SourceKubeconfig, r.ReadErrors[0].Source)
	assert.NotEmpty(t, r.ReadErrors[0].Err)

	// Other keys are unaffected by the failed read.
	assert.Equal(t, "150", findSetting(t, r, "HELM_BURST_LIMIT").Value)
	ns := findSetting(t, r, "HELM_NAMESPACE")
	assert.Equal(t, "default", ns.Value)
	assert.Equal(t, SourceDefault, winningSource(t, ns).Type)
}

func TestProvenanceSensitiveValuesAreRedacted(t *testing.T) {
	s, r := newProvenanceSettings(t, "", map[string]string{"HELM_KUBETOKEN": "super-secret-token"})
	assert.Equal(t, "super-secret-token", s.KubeToken)

	token := findSetting(t, r, "HELM_KUBETOKEN")
	assert.Equal(t, redactedValue, token.Value)
	for _, src := range token.Sources {
		assert.NotEqual(t, "super-secret-token", src.RawValue)
		assert.NotEqual(t, "super-secret-token", src.Value)
	}

	var buf bytes.Buffer
	require.NoError(t, WriteReport(&buf, r, ""))
	assert.NotContains(t, buf.String(), "super-secret-token")
}

func TestProvenanceColorSources(t *testing.T) {
	t.Run("no_color overrides helm_color", func(t *testing.T) {
		s, r := newProvenanceSettings(t, "", map[string]string{
			"NO_COLOR":   "1",
			"HELM_COLOR": "always",
		})
		assert.Equal(t, "never", s.ColorMode)
		color := findSetting(t, r, "HELM_COLOR")
		assert.Equal(t, "never", color.Value)
		assert.Equal(t, "NO_COLOR", winningSource(t, color).Location)
		var conflict *Conflict
		for i := range r.Conflicts {
			if r.Conflicts[i].Key == "HELM_COLOR" {
				conflict = &r.Conflicts[i]
			}
		}
		require.NotNil(t, conflict)
		assert.Len(t, conflict.Values, 2)
	})

	t.Run("invalid helm color falls back and is diagnosed", func(t *testing.T) {
		s, r := newProvenanceSettings(t, "", map[string]string{"HELM_COLOR": "bogus"})
		assert.Equal(t, "auto", s.ColorMode)
		require.Len(t, r.Invalid, 1)
		assert.Equal(t, "HELM_COLOR", r.Invalid[0].Key)
		assert.Contains(t, r.Invalid[0].Expected, "never")
	})

	t.Run("colour flag binds the color key", func(t *testing.T) {
		s, r := newProvenanceSettings(t, "--colour=always", map[string]string{})
		assert.Equal(t, "always", s.ColorMode)
		color := findSetting(t, r, "HELM_COLOR")
		assert.Equal(t, "--colour", winningSource(t, color).Location)
	})
}

func TestProvenanceSemanticValidation(t *testing.T) {
	_, r := newProvenanceSettings(t, "", map[string]string{"HELM_MAX_HISTORY": "-3"})
	require.Len(t, r.Invalid, 1)
	assert.Equal(t, "HELM_MAX_HISTORY", r.Invalid[0].Key)
	assert.Contains(t, r.Invalid[0].Reason, "0 or greater")

	_, r2 := newProvenanceSettings(t, "--qps=-0.5", map[string]string{})
	require.Len(t, r2.Invalid, 1)
	assert.Equal(t, "HELM_QPS", r2.Invalid[0].Key)
	assert.Equal(t, SourceFlag, r2.Invalid[0].Source)
	assert.Equal(t, "--qps", r2.Invalid[0].Location)

	// -1 is a documented, valid value for the burst limit.
	_, r3 := newProvenanceSettings(t, "", map[string]string{"HELM_BURST_LIMIT": "-1"})
	assert.Empty(t, r3.Invalid)
}

func TestProvenanceCSVGroups(t *testing.T) {
	_, r := newProvenanceSettings(t, "--kube-as-group=x --kube-as-group=y", map[string]string{
		"HELM_KUBEASGROUPS": ",a,b,",
	})
	groups := findSetting(t, r, "HELM_KUBEASGROUPS")
	assert.Equal(t, "x,y", groups.Value)
	env, ok := findSourceByLocation(groups, "HELM_KUBEASGROUPS")
	require.True(t, ok)
	assert.Equal(t, "a,b", env.Value)
	require.Len(t, r.Conflicts, 1)
	assert.Equal(t, "HELM_KUBEASGROUPS", r.Conflicts[0].Key)
}

func TestProvenanceReportMatchesEffectiveFields(t *testing.T) {
	s, r := newProvenanceSettings(t,
		"--debug --namespace=myns --burst-limit=175 --qps=70 --kube-as-group=a",
		map[string]string{
			"HELM_BURST_LIMIT": "200",
			"HELM_PLUGINS":     filepath.FromSlash("/my/plugins"),
		})

	for _, info := range r.Settings {
		assert.Equal(t, s.canonicalValue(info.Key), info.Value, info.Key)
	}

	// The values exported to plugin subprocesses through EnvVars must match
	// the report for every key EnvVars covers.
	envVars := s.EnvVars()
	for _, info := range r.Settings {
		// HELM_COLOR is not exported by EnvVars; KUBECONFIG is only exported
		// when non-empty; HELM_KUBETOKEN is intentionally redacted here.
		if info.Key == "HELM_COLOR" || info.Key == "HELM_KUBETOKEN" || info.Key == "KUBECONFIG" {
			continue
		}
		envValue, ok := envVars[info.Key]
		require.True(t, ok, info.Key)
		assert.Equal(t, envValue, info.Value, info.Key)
	}
}

func TestProvenanceKeys(t *testing.T) {
	s, _ := newProvenanceSettings(t, "", map[string]string{})
	keys := s.Keys()
	assert.Len(t, keys, 23)
	assert.True(t, sort.StringsAreSorted(keys))
	assert.Contains(t, keys, "HELM_NAMESPACE")
	assert.Contains(t, keys, "KUBECONFIG")
}

func TestWriteReport(t *testing.T) {
	_, r := newProvenanceSettings(t, "--debug", map[string]string{"HELM_BURST_LIMIT": "150"})

	var all bytes.Buffer
	require.NoError(t, WriteReport(&all, r, ""))
	text := all.String()
	assert.Contains(t, text, "EFFECTIVE CLI SETTINGS")
	assert.Contains(t, text, "HELM_BURST_LIMIT=150")
	assert.Contains(t, text, "SUMMARY")

	var single bytes.Buffer
	require.NoError(t, WriteReport(&single, r, "HELM_BURST_LIMIT"))
	assert.Contains(t, single.String(), "HELM_BURST_LIMIT")
	assert.Contains(t, single.String(), "effective value")
	assert.Contains(t, single.String(), "150")

	var bad bytes.Buffer
	require.Error(t, WriteReport(&bad, r, "DOES_NOT_EXIST"))
}
