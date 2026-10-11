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
	"fmt"
	"strings"

	"helm.sh/helm/v4/pkg/downloader"
	"helm.sh/helm/v4/pkg/provenance"
)

// Verify is the action for building a given chart's Verify tree.
//
// It provides the implementation of 'helm verify'.
type Verify struct {
	// Keyring is the single keyring used by the legacy behavior.
	Keyring string
	// KeyringExplicit reports whether Keyring was passed explicitly; an
	// implicit default keyring is not pulled into a declared policy.
	KeyringExplicit bool

	// PolicyFiles are verification policy files merged in order.
	PolicyFiles []string
	// ExtraKeyrings adds command-line keyring files.
	ExtraKeyrings []string
	// KeyDirs adds command-line key directories.
	KeyDirs []string

	// IdentityAllow, IdentityDeny and IdentityRequiredPatterns override the
	// identity admission lists supplied by policy files.
	IdentityAllow            []string
	IdentityDeny             []string
	IdentityRequiredPatterns []string
	// FingerprintAllow, FingerprintDeny and FingerprintRequiredPatterns
	// override the fingerprint admission lists supplied by policy files.
	FingerprintAllow            []string
	FingerprintDeny             []string
	FingerprintRequiredPatterns []string

	// MinValidSignatures and MinDistinctSources, when positive, override the
	// policy-file thresholds.
	MinValidSignatures int
	MinDistinctSources int

	// RequiredAnnotations, when non-nil, overrides the policy-file required
	// signature annotations.
	RequiredAnnotations map[string]string
}

// NewVerify creates a new Verify object with the given configuration.
func NewVerify() *Verify {
	return &Verify{}
}

// policyEnabled reports whether any policy-only input was supplied. When
// false, verification follows the historical single-keyring behavior exactly.
func (v *Verify) policyEnabled() bool {
	return len(v.PolicyFiles) > 0 ||
		len(v.ExtraKeyrings) > 0 ||
		len(v.KeyDirs) > 0 ||
		len(v.IdentityAllow) > 0 ||
		len(v.IdentityDeny) > 0 ||
		len(v.IdentityRequiredPatterns) > 0 ||
		len(v.FingerprintAllow) > 0 ||
		len(v.FingerprintDeny) > 0 ||
		len(v.FingerprintRequiredPatterns) > 0 ||
		v.MinValidSignatures > 0 ||
		v.MinDistinctSources > 0 ||
		v.RequiredAnnotations != nil
}

// Run executes 'helm verify'.
func (v *Verify) Run(chartfile string) (string, error) {
	if !v.policyEnabled() {
		return v.runLegacy(chartfile)
	}
	return v.runWithPolicy(chartfile)
}

// runLegacy preserves the historical single-keyring behavior and output
// byte-for-byte.
func (v *Verify) runLegacy(chartfile string) (string, error) {
	var out strings.Builder
	p, err := downloader.VerifyChart(chartfile, chartfile+".prov", v.Keyring)
	if err != nil {
		return "", err
	}

	for name := range p.SignedBy.Identities {
		_, _ = fmt.Fprintf(&out, "Signed by: %v\n", name)
	}
	_, _ = fmt.Fprintf(&out, "Using Key With Fingerprint: %X\n", p.SignedBy.PrimaryKey.Fingerprint)
	_, _ = fmt.Fprintf(&out, "Chart Hash Verified: %s\n", p.FileHash)

	return out.String(), err
}

// runWithPolicy merges the declared key sources and admission rules,
// verifies every signature block and appends the policy report.
func (v *Verify) runWithPolicy(chartfile string) (string, error) {
	primaryKeyring := ""
	if v.KeyringExplicit {
		primaryKeyring = v.Keyring
	}

	ov := &provenance.PolicyOverrides{
		ExtraKeyrings: v.ExtraKeyrings,
		KeyDirs:       v.KeyDirs,
		Identities: provenance.Admission{
			Allow:            v.IdentityAllow,
			Deny:             v.IdentityDeny,
			RequiredPatterns: v.IdentityRequiredPatterns,
		},
		Fingerprints: provenance.Admission{
			Allow:            v.FingerprintAllow,
			Deny:             v.FingerprintDeny,
			RequiredPatterns: v.FingerprintRequiredPatterns,
		},
		RequiredAnnotations: v.RequiredAnnotations,
	}
	if v.MinValidSignatures > 0 {
		n := v.MinValidSignatures
		ov.MinValidSignatures = &n
	}
	if v.MinDistinctSources > 0 {
		n := v.MinDistinctSources
		ov.MinDistinctSources = &n
	}

	eff, err := provenance.BuildEffectivePolicy(primaryKeyring, v.PolicyFiles, ov)
	if err != nil {
		return "", err
	}

	sig := provenance.NewPolicySignatory(eff)
	res, err := downloader.VerifyChartWithPolicy(chartfile, chartfile+".prov", sig)
	if err != nil {
		return "", err
	}

	var out strings.Builder

	// Preserve the existing output fields, one block per admitted signer.
	printedHash := false
	for i := range res.Judgments {
		j := &res.Judgments[i]
		if j.Reason != provenance.ReasonAdmitted {
			continue
		}
		for _, name := range j.Identities {
			_, _ = fmt.Fprintf(&out, "Signed by: %v\n", name)
		}
		_, _ = fmt.Fprintf(&out, "Using Key With Fingerprint: %s\n", j.Fingerprint)
		if !printedHash {
			_, _ = fmt.Fprintf(&out, "Chart Hash Verified: %s\n", j.RecordedDigest)
			printedHash = true
		}
	}

	out.WriteString(res.Report())

	if err := res.FailureError(); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}
