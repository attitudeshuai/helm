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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"helm.sh/helm/v4/pkg/cli"
)

// useFreshSettings clears the environment, rebuilds the global settings from
// the test environment and restores the original settings afterwards.
func useFreshSettings(t *testing.T) {
	t.Helper()
	saved := settings
	settings = cli.New()
	t.Cleanup(func() { settings = saved })
}

func TestSettingsReport(t *testing.T) {
	defer resetEnv()()
	t.Setenv("HELM_BURST_LIMIT", "150")
	useFreshSettings(t)

	_, out, err := executeActionCommand("settings")
	require.NoError(t, err)
	assert.Contains(t, out, "EFFECTIVE CLI SETTINGS")
	assert.Contains(t, out, "HELM_BURST_LIMIT=150")
	assert.Contains(t, out, "environment variable HELM_BURST_LIMIT")
	assert.Contains(t, out, "[external]")
	assert.Contains(t, out, "SUMMARY")
}

func TestSettingsReportSingleKey(t *testing.T) {
	defer resetEnv()()
	t.Setenv("HELM_BURST_LIMIT", "200")
	useFreshSettings(t)

	_, out, err := executeActionCommand("settings HELM_BURST_LIMIT")
	require.NoError(t, err)
	assert.Contains(t, out, "HELM_BURST_LIMIT")
	assert.Contains(t, out, "effective value: \"200\"")
	assert.Contains(t, out, "environment variable HELM_BURST_LIMIT")
}

func TestSettingsReportUnknownKey(t *testing.T) {
	defer resetEnv()()
	useFreshSettings(t)

	_, _, err := executeActionCommand("settings DOES_NOT_EXIST")
	require.Error(t, err)
}

func TestSettingsReportInvalidValue(t *testing.T) {
	defer resetEnv()()
	t.Setenv("HELM_QPS", "bogus")
	useFreshSettings(t)

	// Without strict mode the command succeeds and the report points out the
	// invalid value and its source.
	_, out, err := executeActionCommand("settings")
	require.NoError(t, err)
	assert.Contains(t, out, "Invalid values:")
	assert.Contains(t, out, "HELM_QPS")
	assert.Contains(t, out, "HELM_QPS")
	assert.Contains(t, out, "environment variable HELM_QPS")
	assert.Contains(t, out, "floating-point")
}

func TestSettingsKeyCompletion(t *testing.T) {
	defer resetEnv()()
	useFreshSettings(t)

	_, out, err := executeActionCommand("__complete settings ''")
	require.NoError(t, err)
	assert.Contains(t, out, "HELM_NAMESPACE")
	assert.Contains(t, out, "HELM_BURST_LIMIT")
}

func TestStrictSettingsGate(t *testing.T) {
	defer resetEnv()()
	t.Setenv("HELM_QPS", "bogus")
	useFreshSettings(t)

	// Fallback behavior stays unchanged without the flag.
	_, _, err := executeActionCommand("version")
	require.NoError(t, err)

	// The flag fails the command with key, raw value, source and expected
	// format all visible.
	_, out, err := executeActionCommand("version --strict-settings")
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "HELM_QPS")
	assert.Contains(t, msg, "bogus")
	assert.Contains(t, msg, "HELM_QPS")
	assert.Contains(t, msg, "environment variable")
	assert.NotContains(t, out, "bogus")
}

func TestStrictSettingsGateValid(t *testing.T) {
	defer resetEnv()()
	t.Setenv("HELM_QPS", "42")
	useFreshSettings(t)

	_, _, err := executeActionCommand("version --strict-settings")
	require.NoError(t, err)
}
