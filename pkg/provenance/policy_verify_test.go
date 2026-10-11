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
	"bytes"
	"crypto"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

type policyFixture struct {
	vendor   *openpgp.Entity
	internal *openpgp.Entity
	outside  *openpgp.Entity
	archive  []byte
	message  []byte
	filename string
}

func newPolicyFixture(t *testing.T) *policyFixture {
	t.Helper()
	mk := func(name, comment, email string) *openpgp.Entity {
		e, err := openpgp.NewEntity(name, comment, email, nil)
		require.NoError(t, err)
		return e
	}
	fx := &policyFixture{
		vendor:   mk("Acme Vendor", "chart signing", "vendor@acme.example"),
		internal: mk("Internal Platform", "platform signing", "platform@internal.example"),
		outside:  mk("Outsider", "unknown", "outsider@elsewhere.example"),
		filename: filepath.Base(testChartfile),
	}
	fx.archive = mustReadFile(t, testChartfile)
	metadata := loadChartMetadataForSigning(t, testChartfile)
	msg, err := messageBlock(fx.archive, fx.filename, metadata)
	require.NoError(t, err)
	fx.message = msg.Bytes()
	return fx
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

// writeArmoredPublicKey writes one entity's armored public key and returns the
// path.
func writeArmoredPublicKey(t *testing.T, dir, name string, e *openpgp.Entity) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	require.NoError(t, err)
	require.NoError(t, e.Serialize(w))
	require.NoError(t, w.Close())
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, buf.Bytes(), 0o644))
	return p
}

// signBlock clearsigns message with e, optionally carrying notations.
func signBlock(t *testing.T, e *openpgp.Entity, message []byte, notations map[string]string) []byte {
	t.Helper()
	cfg := &packet.Config{DefaultHash: crypto.SHA512}
	for k, v := range notations {
		cfg.SignatureNotations = append(cfg.SignatureNotations, &packet.Notation{
			Name: k, Value: []byte(v), IsHumanReadable: true,
		})
	}
	var buf bytes.Buffer
	w, err := clearsign.Encode(&buf, e.PrivateKey, cfg)
	require.NoError(t, err)
	_, err = io.Copy(w, bytes.NewReader(message))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// policyFromYAML writes a policy document, loads it and returns the effective
// policy together with the policy file origin label.
func policyFromYAML(t *testing.T, dir, doc string, ov *PolicyOverrides) (*EffectivePolicy, string) {
	t.Helper()
	path := writePolicyFile(t, dir, "policy.yaml", doc)
	eff, err := BuildEffectivePolicy("", []string{path}, ov)
	require.NoError(t, err)
	return eff, path
}

func verifyFixture(t *testing.T, fx *policyFixture, eff *EffectivePolicy, prov []byte) *PolicyVerification {
	t.Helper()
	ps := NewPolicySignatory(eff)
	res, err := ps.VerifyPolicy(fx.archive, prov, fx.filename)
	require.NoError(t, err)
	return res
}

func (fx *policyFixture) block(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	return signBlock(t, e, fx.message, nil)
}

func (fx *policyFixture) annotatedBlock(t *testing.T, e *openpgp.Entity, annotations map[string]string) []byte {
	t.Helper()
	return signBlock(t, e, fx.message, annotations)
}

// wrongDigestBlock produces a valid signature over a message block that
// records a different chart digest.
func (fx *policyFixture) wrongDigestBlock(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	metadata := loadChartMetadataForSigning(t, testChartfile)
	msg, err := messageBlock(append(append([]byte(nil), fx.archive...), 0x00), fx.filename, metadata)
	require.NoError(t, err)
	return signBlock(t, e, msg.Bytes(), nil)
}

func TestVerifyPolicySingleSignaturePass(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	vendorKey := writeArmoredPublicKey(t, dir, "vendor.asc", fx.vendor)
	eff, origin := policyFromYAML(t, dir, "keySources:\n  - name: vendor\n    path: "+vendorKey+"\n", nil)

	res := verifyFixture(t, fx, eff, fx.block(t, fx.vendor))
	assert.Equal(t, StatusVerified, res.Status, res.Message)
	assert.Equal(t, 1, res.ValidSignatures)
	require.Len(t, res.Judgments, 1)
	j := res.Judgments[0]
	assert.True(t, j.CryptographicallyValid && j.DigestMatches && j.Admitted)
	assert.Equal(t, ReasonAdmitted, j.Reason)
	assert.Equal(t, []string{"vendor"}, j.Sources)
	assert.Contains(t, j.Identities, "Acme Vendor (chart signing) <vendor@acme.example>")
	report := res.Report()
	assert.NotEmpty(t, report)
	assert.Contains(t, report, "from \""+origin+"\"")
	assert.Contains(t, report, "Result: verification passed")
	assert.NotContains(t, report, packet.SaltNotationName)
}

func TestVerifyPolicyMultiSignatureFromTwoSources(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	vendorKey := writeArmoredPublicKey(t, dir, "vendor.asc", fx.vendor)
	internalKey := writeArmoredPublicKey(t, dir, "internal.asc", fx.internal)
	doc := "keySources:\n  - name: vendor\n    path: " + vendorKey + "\n  - name: internal\n    path: " + internalKey +
		"\nminValidSignatures: 2\nminDistinctSources: 2\n"
	eff, _ := policyFromYAML(t, dir, doc, nil)

	prov := append(fx.block(t, fx.vendor), fx.block(t, fx.internal)...)
	res := verifyFixture(t, fx, eff, prov)
	assert.Equal(t, StatusVerified, res.Status, res.Message)
	assert.Equal(t, 2, res.ValidSignatures)
	assert.ElementsMatch(t, []string{"vendor", "internal"}, res.DistinctSources)
}

func TestVerifyPolicyDenyIdentity(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	vendorKey := writeArmoredPublicKey(t, dir, "vendor.asc", fx.vendor)
	eff, origin := policyFromYAML(t, dir,
		"keySources:\n  - path: "+vendorKey+"\nidentities:\n  deny:\n    - vendor@acme.example\n", nil)

	res := verifyFixture(t, fx, eff, fx.block(t, fx.vendor))
	assert.Equal(t, StatusSignerForbidden, res.Status)
	assert.Contains(t, res.Message, "vendor@acme.example")
	assert.Contains(t, res.Message, "deny list")
	assert.Contains(t, res.Message, origin)
	assert.Equal(t, reasonDeniedIdentity, res.Judgments[0].Reason)
	assert.False(t, res.Judgments[0].Admitted)
}

func TestVerifyPolicyAllowListExcludesOutsider(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	outsideKey := writeArmoredPublicKey(t, dir, "outside.asc", fx.outside)
	eff, _ := policyFromYAML(t, dir,
		"keySources:\n  - path: "+outsideKey+"\nidentities:\n  allow:\n    - platform@internal.example\n", nil)

	res := verifyFixture(t, fx, eff, fx.block(t, fx.outside))
	assert.Equal(t, StatusSignerForbidden, res.Status)
	assert.Contains(t, res.Message, "is in the identity allow list")
	assert.Equal(t, reasonIdentityNotAllowed, res.Judgments[0].Reason)
}

func TestVerifyPolicyInsufficientValidSignatures(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	key := writeArmoredPublicKey(t, dir, "vendor.asc", fx.vendor)
	eff, _ := policyFromYAML(t, dir,
		"keySources:\n  - name: vendor\n    path: "+key+"\nminValidSignatures: 2\n", nil)

	res := verifyFixture(t, fx, eff, fx.block(t, fx.vendor))
	assert.Equal(t, StatusInsufficientSignatures, res.Status)
	assert.Contains(t, res.Message, "insufficient valid signatures: found 1")
	assert.Contains(t, res.Message, "required 2")
	assert.Contains(t, res.Message, "Acme Vendor")
	assert.Equal(t, 1, res.ValidSignatures)
	assert.Equal(t, 2, res.RequiredValidSignatures)
}

func TestVerifyPolicyInsufficientDistinctSources(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	// Both keys live in the same key directory, i.e. a single source.
	keydir := filepath.Join(dir, "keys")
	require.NoError(t, os.Mkdir(keydir, 0o755))
	writeArmoredPublicKey(t, keydir, "vendor.asc", fx.vendor)
	writeArmoredPublicKey(t, keydir, "internal.asc", fx.internal)
	eff, _ := policyFromYAML(t, dir,
		"keySources:\n  - name: bundle\n    path: "+keydir+"\nminValidSignatures: 2\nminDistinctSources: 2\n", nil)

	prov := append(fx.block(t, fx.vendor), fx.block(t, fx.internal)...)
	res := verifyFixture(t, fx, eff, prov)
	assert.Equal(t, StatusInsufficientSignatures, res.Status)
	assert.Contains(t, res.Message, "insufficient distinct key sources: found 1")
	assert.Contains(t, res.Message, "bundle")
	assert.Contains(t, res.Message, "required 2")
}

func TestVerifyPolicyUnknownSigner(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	known := writeArmoredPublicKey(t, dir, "known.asc", fx.internal)
	eff, _ := policyFromYAML(t, dir, "keySources:\n  - path: "+known+"\n", nil)

	res := verifyFixture(t, fx, eff, fx.block(t, fx.vendor))
	assert.Equal(t, StatusUnknownSigner, res.Status)
	assert.Contains(t, res.Message, "no signature could be verified")
	assert.Contains(t, res.Message, "unknown signers")
	j := res.Judgments[0]
	assert.False(t, j.KnownSigner)
	assert.Equal(t, reasonUnknownSigner, j.Reason)
	assert.NotEmpty(t, j.IssuerKeyID)
	assert.Contains(t, res.Report(), "unknown signer (issuer key 0x"+j.IssuerKeyID+")")
}

func TestVerifyPolicyDigestMismatchIsSeparateFromUnknown(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	key := writeArmoredPublicKey(t, dir, "vendor.asc", fx.vendor)
	eff, _ := policyFromYAML(t, dir, "keySources:\n  - path: "+key+"\n", nil)

	res := verifyFixture(t, fx, eff, fx.wrongDigestBlock(t, fx.vendor))
	assert.Equal(t, StatusDigestMismatch, res.Status)
	assert.Contains(t, res.Message, "digest does not match")
	j := res.Judgments[0]
	assert.True(t, j.CryptographicallyValid)
	assert.False(t, j.DigestMatches)
	assert.Equal(t, reasonDigestMismatch, j.Reason)
	assert.NotEqual(t, j.RecordedDigest, j.ChartDigest)
}

func TestVerifyPolicyUnparseableKeyringIsIsolated(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	good := writeArmoredPublicKey(t, dir, "good.asc", fx.vendor)
	bad := filepath.Join(dir, "broken.asc")
	require.NoError(t, os.WriteFile(bad, []byte("this is definitely not a keyring"), 0o644))

	eff, err := BuildEffectivePolicy("", nil, &PolicyOverrides{
		ExtraKeyrings: []string{bad, good},
	})
	require.NoError(t, err)

	ps := NewPolicySignatory(eff)
	res, err := ps.VerifyPolicy(fx.archive, fx.block(t, fx.vendor), fx.filename)
	require.NoError(t, err)
	assert.Equal(t, StatusVerified, res.Status, res.Message)

	var counted, notCounted int
	for _, r := range ps.loadResults {
		if r.Counted {
			counted++
		} else {
			notCounted++
			assert.Equal(t, bad, r.Path)
			assert.NotEmpty(t, r.Reason)
		}
	}
	assert.Equal(t, 1, counted)
	assert.Equal(t, 1, notCounted)

	report := res.Report()
	assert.Contains(t, report, "Key Sources Counted: 1")
	assert.Contains(t, report, "Not Counted: 1")
	assert.Contains(t, report, bad)
}

func TestVerifyPolicyKeyDirectory(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	keydir := filepath.Join(dir, "keys")
	require.NoError(t, os.Mkdir(keydir, 0o755))
	writeArmoredPublicKey(t, keydir, "vendor.asc", fx.vendor)
	// Non-key files in a directory are reported but do not break loading.
	require.NoError(t, os.WriteFile(filepath.Join(keydir, "README.txt"), []byte("notes"), 0o644))

	eff, err := BuildEffectivePolicy("", nil, &PolicyOverrides{KeyDirs: []string{keydir}})
	require.NoError(t, err)
	ps := NewPolicySignatory(eff)

	for _, r := range ps.loadResults {
		assert.True(t, r.IsDir)
		assert.True(t, r.Counted)
		require.Len(t, r.FileErrors, 1)
		assert.Contains(t, r.FileErrors[0].Path, "README.txt")
	}

	res, err := ps.VerifyPolicy(fx.archive, fx.block(t, fx.vendor), fx.filename)
	require.NoError(t, err)
	assert.Equal(t, StatusVerified, res.Status, res.Message)
	assert.Contains(t, res.Report(), "Key Source File Not Counted")
}

func TestVerifyPolicySameKeyAcrossSourcesNotDoubleCounted(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	first := writeArmoredPublicKey(t, dir, "a.asc", fx.vendor)
	second := writeArmoredPublicKey(t, dir, "b.asc", fx.vendor)
	eff, err := BuildEffectivePolicy("", nil, &PolicyOverrides{ExtraKeyrings: []string{first, second}})
	require.NoError(t, err)
	ps := NewPolicySignatory(eff)

	// One signature block.
	res, err := ps.VerifyPolicy(fx.archive, fx.block(t, fx.vendor), fx.filename)
	require.NoError(t, err)
	assert.Equal(t, StatusVerified, res.Status, res.Message)
	assert.Equal(t, 1, res.ValidSignatures, "the same public key must count once")
	assert.ElementsMatch(t, []string{first, second}, res.Judgments[0].Sources)

	// Two signature blocks by the same key still count once.
	res2, err := ps.VerifyPolicy(fx.archive,
		append(fx.block(t, fx.vendor), fx.block(t, fx.vendor)...), fx.filename)
	require.NoError(t, err)
	assert.Equal(t, 1, res2.ValidSignatures)
	assert.Equal(t, ReasonAdmitted, res2.Judgments[0].Reason)
	assert.Equal(t, reasonDuplicate, res2.Judgments[1].Reason)
}

func TestVerifyPolicyRequiredAnnotations(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	key := writeArmoredPublicKey(t, dir, "vendor.asc", fx.vendor)

	build := func(t *testing.T, annotations map[string]string) *PolicyVerification {
		t.Helper()
		docYAML, err := yaml.Marshal(&Policy{
			KeySources:          []KeySource{{Path: key}},
			RequiredAnnotations: annotations,
		})
		require.NoError(t, err)
		eff, _ := policyFromYAML(t, dir, string(docYAML), nil)
		return verifyFixture(t, fx, eff, fx.annotatedBlock(t, fx.vendor,
			map[string]string{"helm.sh/purpose": "release"}))
	}

	// Present, value-agnostic (empty value).
	res := build(t, map[string]string{"helm.sh/purpose": ""})
	assert.Equal(t, StatusVerified, res.Status, res.Message)
	assert.Equal(t, "release", res.Judgments[0].Annotations["helm.sh/purpose"])

	// Present with the expected value.
	res = build(t, map[string]string{"helm.sh/purpose": "release"})
	assert.Equal(t, StatusVerified, res.Status, res.Message)

	// Present but wrong value.
	res = build(t, map[string]string{"helm.sh/purpose": "canary"})
	assert.Equal(t, StatusSignerForbidden, res.Status)
	assert.Contains(t, res.Message, "expected \"canary\"")

	// Missing entirely.
	res = build(t, map[string]string{"helm.sh/scope": "all"})
	assert.Equal(t, StatusSignerForbidden, res.Status)
	assert.Contains(t, res.Message, "does not carry required annotation")
}

func TestVerifyPolicyFingerprintDeny(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	key := writeArmoredPublicKey(t, dir, "vendor.asc", fx.vendor)
	fp := fingerprintOf(fx.vendor)
	eff, _ := policyFromYAML(t, dir,
		"keySources:\n  - path: "+key+"\nfingerprints:\n  deny:\n    - \""+fp[len(fp)-8:]+"\"\n", nil)

	res := verifyFixture(t, fx, eff, fx.block(t, fx.vendor))
	assert.Equal(t, StatusSignerForbidden, res.Status)
	assert.Equal(t, reasonDeniedFingerprint, res.Judgments[0].Reason)
}

func TestVerifyPolicyRequiredIdentityPattern(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	key := writeArmoredPublicKey(t, dir, "vendor.asc", fx.vendor)
	eff, _ := policyFromYAML(t, dir,
		"keySources:\n  - path: "+key+"\nidentities:\n  requiredPatterns:\n    - '@acme\\.example>$'\n", nil)
	res := verifyFixture(t, fx, eff, fx.block(t, fx.vendor))
	assert.Equal(t, StatusVerified, res.Status, res.Message)

	eff, _ = policyFromYAML(t, dir,
		"keySources:\n  - path: "+key+"\nidentities:\n  requiredPatterns:\n    - '@internal\\.example>$'\n", nil)
	res = verifyFixture(t, fx, eff, fx.block(t, fx.vendor))
	assert.Equal(t, StatusSignerForbidden, res.Status)
	assert.Equal(t, reasonIdentityPattern, res.Judgments[0].Reason)
}

func TestVerifyPolicyMissingSignatureBlock(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	key := writeArmoredPublicKey(t, dir, "vendor.asc", fx.vendor)
	eff, _ := policyFromYAML(t, dir, "keySources:\n  - path: "+key+"\n", nil)

	ps := NewPolicySignatory(eff)
	_, err := ps.VerifyPolicy(fx.archive, []byte("nothing to see here"), fx.filename)
	require.Error(t, err)
	assert.EqualError(t, err, "signature block not found")
}

func TestVerifyPolicyCLISupersessionVisibleInReport(t *testing.T) {
	fx := newPolicyFixture(t)
	dir := t.TempDir()
	vendorKey := writeArmoredPublicKey(t, dir, "vendor.asc", fx.vendor)
	doc := "keySources:\n  - path: " + vendorKey + "\nidentities:\n  deny:\n    - old@example.com\nminValidSignatures: 1\n"
	path := writePolicyFile(t, dir, "policy.yaml", doc)

	minValid := 1
	eff, err := BuildEffectivePolicy("", []string{path}, &PolicyOverrides{
		Identities:         Admission{Deny: []string{"vendor@acme.example"}},
		MinValidSignatures: &minValid,
	})
	require.NoError(t, err)

	res := verifyFixture(t, fx, eff, fx.block(t, fx.vendor))
	assert.Equal(t, StatusSignerForbidden, res.Status)
	report := res.Report()
	assert.Contains(t, report, "Identity Deny: vendor@acme.example (from command-line)")
	assert.Contains(t, report, "identity deny list from \""+path+"\" was superseded by command-line")
	assert.Contains(t, report, "Minimum Valid Signatures: 1 (from command-line)")
}
