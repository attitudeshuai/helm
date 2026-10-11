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

package action

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	verifyTestChart = "../downloader/testdata/signtest-0.1.0.tgz"
	verifyTestKey   = "../downloader/testdata/helm-test-key.pub"
)

func TestNewVerify(t *testing.T) {
	client := NewVerify()

	assert.NotNil(t, client)
}

func TestVerifyRun(t *testing.T) {
	client := NewVerify()

	client.Keyring = "../downloader/testdata/helm-test-key.pub"
	output, err := client.Run("../downloader/testdata/signtest-0.1.0.tgz")
	assert.Contains(t, output, "Signed by:")
	assert.Contains(t, output, "Using Key With Fingerprint:")
	assert.Contains(t, output, "Chart Hash Verified:")
	require.NoError(t, err)
}

func TestVerifyRun_DownloadError(t *testing.T) {
	client := NewVerify()
	output, err := client.Run("invalid-chart-path")
	require.Error(t, err)
	assert.Empty(t, output)
}

func TestVerifyRunWithExtraKeyring(t *testing.T) {
	client := NewVerify()
	client.ExtraKeyrings = []string{verifyTestKey}

	output, err := client.Run(verifyTestChart)
	require.NoError(t, err)
	// The legacy fields are unchanged.
	assert.Contains(t, output, "Signed by:")
	assert.Contains(t, output, "Using Key With Fingerprint:")
	assert.Contains(t, output, "Chart Hash Verified:")
	// The policy supplement identifies the source, the judged signer and the
	// result.
	assert.Contains(t, output, "Verification Policy:")
	assert.Contains(t, output, "Key Source:")
	assert.Contains(t, output, "Key Sources Counted: 1")
	assert.Contains(t, output, "Judged Signatures:")
	assert.Contains(t, output, "Verdict: admitted")
	assert.Contains(t, output, "Result: verification passed")
}

func TestVerifyRunPolicyFile(t *testing.T) {
	absKey, err := filepath.Abs(verifyTestKey)
	require.NoError(t, err)
	dir := t.TempDir()
	policy := "keySources:\n  - name: helm-test\n    path: " + absKey + "\n"
	policyPath := filepath.Join(dir, "verify-policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(policy), 0o644))

	client := NewVerify()
	client.PolicyFiles = []string{policyPath}
	output, err := client.Run(verifyTestChart)
	require.NoError(t, err)
	assert.Contains(t, output, "Key Source: helm-test")
	assert.Contains(t, output, "from \""+policyPath+"\"")
	assert.Contains(t, output, "Result: verification passed")
}

func TestVerifyRunDenyIdentity(t *testing.T) {
	client := NewVerify()
	client.ExtraKeyrings = []string{verifyTestKey}
	client.IdentityDeny = []string{"helm-testing@helm.sh"}

	_, err := client.Run(verifyTestChart)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
	assert.Contains(t, err.Error(), "signer-forbidden")
	detail := err.Error()
	assert.Contains(t, detail, "deny list entry \"helm-testing@helm.sh\"")
	assert.Contains(t, detail, "Judged Signatures:")
	assert.Contains(t, detail, "Identity Deny: helm-testing@helm.sh (from command-line)")
}

func TestVerifyRunMinValidSignaturesCLIOverride(t *testing.T) {
	client := NewVerify()
	client.ExtraKeyrings = []string{verifyTestKey}
	client.MinValidSignatures = 2

	_, err := client.Run(verifyTestChart)
	require.Error(t, err)
	detail := err.Error()
	assert.Contains(t, detail, "insufficient valid signatures: found 1")
	assert.Contains(t, detail, "required 2")
	assert.Contains(t, detail, "Minimum Valid Signatures: 2 (from command-line)")
}

func TestVerifyRunBrokenKeyringIsolated(t *testing.T) {
	// One unparseable keyring is reported as not counted but does not abort
	// verification; the other keyring still validates the chart.
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.asc")
	require.NoError(t, os.WriteFile(broken, []byte("not a keyring"), 0o644))

	client := NewVerify()
	client.ExtraKeyrings = []string{broken, verifyTestKey}
	output, err := client.Run(verifyTestChart)
	require.NoError(t, err)
	assert.Contains(t, output, "Key Sources Counted: 1")
	assert.Contains(t, output, "Not Counted: 1")
	assert.Contains(t, output, broken)
}
