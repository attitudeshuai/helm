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

package provenance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writePolicyFile(t *testing.T, dir, name, contents string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(contents), 0o644))
	return p
}

func TestLoadPolicy(t *testing.T) {
	dir := t.TempDir()
	p := writePolicyFile(t, dir, "policy.yaml", `
keySources:
  - name: vendor
    path: /etc/helm/keys/vendor.asc
identities:
  allow:
    - vendor@example.com
  deny:
    - revoked@example.com
  requiredPatterns:
    - '@example\.com$'
fingerprints:
  deny:
    - "abcd:1234"
minValidSignatures: 2
minDistinctSources: 2
requiredAnnotations:
  helm.sh/purpose: release
`)
	got, err := LoadPolicy(p)
	require.NoError(t, err)
	require.Len(t, got.KeySources, 1)
	assert.Equal(t, "vendor", got.KeySources[0].Name)
	assert.Equal(t, "/etc/helm/keys/vendor.asc", got.KeySources[0].Path)
	assert.Equal(t, []string{"vendor@example.com"}, got.Identities.Allow)
	assert.Equal(t, []string{"revoked@example.com"}, got.Identities.Deny)
	assert.Equal(t, []string{`@example\.com$`}, got.Identities.RequiredPatterns)
	assert.Equal(t, []string{"abcd:1234"}, got.Fingerprints.Deny)
	assert.Equal(t, 2, got.MinValidSignatures)
	assert.Equal(t, 2, got.MinDistinctSources)
	assert.Equal(t, "release", got.RequiredAnnotations["helm.sh/purpose"])
}

func TestLoadPolicyErrors(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.yaml")
	_, err := LoadPolicy(missing)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read verification policy")

	bad := writePolicyFile(t, dir, "bad.yaml", "keySources: [")
	_, err = LoadPolicy(bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse verification policy")
}

func TestBuildEffectivePolicyMergeFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := writePolicyFile(t, dir, "a.yaml", `
keySources:
  - path: keys-a.asc
identities:
  deny:
    - revoked-a@example.com
minValidSignatures: 1
requiredAnnotations:
  env: prod
`)
	f2 := writePolicyFile(t, dir, "b.yaml", `
keySources:
  - path: keys-b.asc
identities:
  deny:
    - revoked-b@example.com
minValidSignatures: 2
requiredAnnotations:
  env: staging
`)
	eff, err := BuildEffectivePolicy("", []string{f1, f2}, nil)
	require.NoError(t, err)

	require.Len(t, eff.sources, 2)
	assert.Equal(t, "keys-a.asc", eff.sources[0].path)
	assert.Equal(t, f1, eff.sources[0].origins[0])

	assert.Equal(t, []string{"revoked-a@example.com", "revoked-b@example.com"},
		[]string{eff.identityDeny[0].value, eff.identityDeny[1].value})
	assert.Equal(t, f2, eff.identityDeny[1].origin)

	// Last writer wins for scalars, with a supersession note.
	assert.Equal(t, 2, eff.minValid.value)
	assert.Equal(t, f2, eff.minValid.origin)
	assert.Contains(t, strings.Join(eff.notes, "\n"), "minimum valid signatures: 1")

	// Per-key annotation supersession is recorded.
	require.Len(t, eff.annotations, 1)
	assert.Equal(t, "staging", eff.annotations[0].value)
	assert.Equal(t, f2, eff.annotations[0].origin)
	assert.Contains(t, strings.Join(eff.notes, "\n"), `required annotation "env"`)
}

func TestBuildEffectivePolicyPrimaryKeyringAndCLI(t *testing.T) {
	dir := t.TempDir()
	f1 := writePolicyFile(t, dir, "a.yaml", `
keySources:
  - path: file.asc
identities:
  allow:
    - from-file@example.com
minDistinctSources: 2
`)
	minValid := 3
	eff, err := BuildEffectivePolicy("primary.asc", []string{f1}, &PolicyOverrides{
		ExtraKeyrings:      []string{"cli.asc"},
		KeyDirs:            []string{"keydir"},
		Identities:         Admission{Allow: []string{"cli@example.com"}},
		MinValidSignatures: &minValid,
	})
	require.NoError(t, err)

	// primary keyring, file source, CLI file and CLI dir, in that order.
	require.Len(t, eff.sources, 4)
	assert.Equal(t, "primary.asc", eff.sources[0].path)
	assert.Equal(t, OriginCommandLine, eff.sources[0].origins[0])
	assert.Equal(t, f1, eff.sources[1].origins[0])
	assert.Equal(t, "keydir", eff.sources[3].path)

	// CLI list replaces the file list and records the supersession.
	require.Len(t, eff.identityAllow, 1)
	assert.Equal(t, "cli@example.com", eff.identityAllow[0].value)
	assert.Equal(t, OriginCommandLine, eff.identityAllow[0].origin)
	assert.Contains(t, strings.Join(eff.notes, "\n"), "identity allow list")

	assert.Equal(t, 3, eff.minValid.value)
	assert.Equal(t, OriginCommandLine, eff.minValid.origin)
	// The file-set scalar remains effective when not overridden.
	assert.Equal(t, 2, eff.minSources.value)
	assert.Equal(t, f1, eff.minSources.origin)
}

func TestBuildEffectivePolicySameSourceMergesOrigins(t *testing.T) {
	dir := t.TempDir()
	f1 := writePolicyFile(t, dir, "a.yaml", "keySources:\n  - name: vendor\n    path: v.asc\n")
	f2 := writePolicyFile(t, dir, "b.yaml", "keySources:\n  - name: vendor\n    path: v.asc\n")
	eff, err := BuildEffectivePolicy("", []string{f1, f2}, &PolicyOverrides{ExtraKeyrings: []string{"v.asc"}})
	require.NoError(t, err)
	require.Len(t, eff.sources, 1)
	assert.ElementsMatch(t, []string{f1, f2, OriginCommandLine}, eff.sources[0].origins)
}

func TestBuildEffectivePolicyConflict(t *testing.T) {
	dir := t.TempDir()
	f1 := writePolicyFile(t, dir, "a.yaml", "identities:\n  allow:\n    - x@example.com\n")
	f2 := writePolicyFile(t, dir, "b.yaml", "identities:\n  deny:\n    - x@example.com\n")
	_, err := BuildEffectivePolicy("", []string{f1, f2}, nil)
	require.Error(t, err)

	var conflict *PolicyConflictError
	require.ErrorAs(t, err, &conflict)
	assert.Equal(t, "identity", conflict.Kind)
	assert.Equal(t, "x@example.com", conflict.Value)
	assert.Equal(t, f1, conflict.Allow)
	assert.Equal(t, f2, conflict.Deny)
	assert.Contains(t, err.Error(), "conflict")
}

func TestBuildEffectivePolicyFingerprintConflictNormalized(t *testing.T) {
	dir := t.TempDir()
	f1 := writePolicyFile(t, dir, "a.yaml", "fingerprints:\n  allow:\n    - \"aa:bb:cc\"\n")
	f2 := writePolicyFile(t, dir, "b.yaml", "fingerprints:\n  deny:\n    - \"0xAABBCC\"\n")
	_, err := BuildEffectivePolicy("", []string{f1, f2}, nil)
	require.Error(t, err)
	var conflict *PolicyConflictError
	require.ErrorAs(t, err, &conflict)
	assert.Equal(t, "fingerprint", conflict.Kind)
	assert.Equal(t, "AABBCC", conflict.Value)
}

func TestBuildEffectivePolicyBadPattern(t *testing.T) {
	dir := t.TempDir()
	f1 := writePolicyFile(t, dir, "a.yaml", "identities:\n  requiredPatterns:\n    - '['\n")
	_, err := BuildEffectivePolicy("", []string{f1}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid identity pattern")
}

func TestIdentityAndFingerprintMatching(t *testing.T) {
	ids := []string{"Acme Vendor (prod) <vendor@acme.example>"}

	assert.True(t, identityMatches("vendor@acme.example", ids))
	assert.True(t, identityMatches("*@acme.example", ids))
	assert.True(t, identityMatches("Acme Vendor*", ids))
	assert.False(t, identityMatches("other@acme.example", ids))

	fp := "AABBCCDDEE"
	assert.True(t, fingerprintMatches("aa:bb:cc:dd:ee", fp))
	assert.True(t, fingerprintMatches("0xaabbccddee", fp))
	assert.True(t, fingerprintMatches("DDEE", fp)) // key-id suffix
	assert.False(t, fingerprintMatches("AABB", fp))
}

func TestEffectivePolicyThresholdDefaults(t *testing.T) {
	eff, err := BuildEffectivePolicy("", nil, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, eff.minValidThreshold())
	assert.Equal(t, 0, eff.minDistinctSourcesThreshold())
}
