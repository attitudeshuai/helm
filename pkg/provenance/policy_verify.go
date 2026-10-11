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
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// PolicyStatus is the overall outcome of a policy-aware verification.
type PolicyStatus string

const (
	// StatusVerified: every requirement was met.
	StatusVerified PolicyStatus = "verified"
	// StatusDigestMismatch: at least one signature was cryptographically
	// valid but its recorded digest does not match the chart content.
	StatusDigestMismatch PolicyStatus = "digest-mismatch"
	// StatusUnknownSigner: no signature could be verified with a key from a
	// counted source.
	StatusUnknownSigner PolicyStatus = "unknown-signer"
	// StatusInsufficientSignatures: signatures verified, but the valid
	// signature count or the distinct-source count was below the threshold.
	StatusInsufficientSignatures PolicyStatus = "insufficient-signatures"
	// StatusSignerForbidden: a verifiable signer was rejected by admission
	// policy (deny list, allow-list exclusion, required pattern or required
	// annotation).
	StatusSignerForbidden PolicyStatus = "signer-forbidden"
)

// Per-signature judgment reason codes.
const (
	// ReasonAdmitted is the reason code of a signature counted as valid and
	// admitted (duplicate signatures are re-marked ReasonDuplicate).
	ReasonAdmitted = "admitted"

	reasonAdmitted            = ReasonAdmitted
	reasonUnknownSigner       = "unknown-signer"
	reasonInvalidSignature    = "invalid-signature"
	reasonDigestMismatch      = "digest-mismatch"
	reasonDeniedIdentity      = "denied-identity"
	reasonDeniedFingerprint   = "denied-fingerprint"
	reasonIdentityNotAllowed  = "identity-not-allowed"
	reasonFingerprintNotAllow = "fingerprint-not-allowed"
	reasonIdentityPattern     = "identity-pattern-not-matched"
	reasonFingerprintPattern  = "fingerprint-pattern-not-matched"
	reasonMissingAnnotation   = "required-annotation-missing"
	reasonDuplicate           = "duplicate-signature"
)

// SignatureJudgment is the per-signature-block verdict.
type SignatureJudgment struct {
	// Block is the 1-based position of the signature block in the provenance
	// file.
	Block int
	// KnownSigner is true when the signing key is present in the merged
	// keyring.
	KnownSigner bool
	// Identities are the signing key's user IDs, sorted.
	Identities []string
	// Fingerprint is the upper-case hex primary key fingerprint. It is empty
	// for unknown signers.
	Fingerprint string
	// IssuerKeyID is the best-effort hex issuer key id carried by the
	// signature packet.
	IssuerKeyID string
	// Sources lists the key sources the signing key was found in.
	Sources []string
	// Annotations holds the OpenPGP notation data subpackets carried by the
	// signature.
	Annotations map[string]string
	// CryptographicallyValid is true when the signature verifies against a
	// key in the keyring.
	CryptographicallyValid bool
	// DigestMatches is true when the signed provenance records the digest of
	// the chart archive under verification.
	DigestMatches bool
	// Admitted is true when the signature passes every admission rule.
	Admitted bool
	// Reason is the machine-readable verdict code.
	Reason string
	// Basis is the human-readable explanation, including the effective rule
	// that decided the verdict.
	Basis string
	// RecordedDigest and ChartDigest are populated for digest comparisons.
	RecordedDigest string
	ChartDigest    string
}

// PolicyVerification is the structured result of a policy-aware verification.
type PolicyVerification struct {
	// Status is the overall outcome.
	Status PolicyStatus
	// Message is a one-line human-readable explanation of a failure.
	Message string
	// Judgments holds one entry per signature block.
	Judgments []SignatureJudgment
	// SignedBy, FileHash and FileName mirror Verification for the first
	// admitted signature, so existing output keeps its shape.
	SignedBy *openpgp.Entity
	FileHash string
	FileName string

	// ValidSignatures is the number of distinct keys with admitted,
	// digest-matching signatures.
	ValidSignatures int
	// RequiredValidSignatures is the effective threshold.
	RequiredValidSignatures int
	// DistinctSources are the key sources covered by the valid signatures.
	DistinctSources []string
	// RequiredDistinctSources is the effective distinct-source threshold.
	RequiredDistinctSources int

	signatory *PolicySignatory
}

// VerifyPolicy verifies a provenance document that may carry several
// clearsigned signature blocks against the merged keyring and evaluates the
// admission policy.
//
// A missing signature block is a hard error, mirroring Verify; every other
// failure is expressed through the structured result.
func (ps *PolicySignatory) VerifyPolicy(archiveData, provData []byte, filename string) (*PolicyVerification, error) {
	res := &PolicyVerification{
		RequiredValidSignatures: ps.policy.minValidThreshold(),
		RequiredDistinctSources: ps.policy.minDistinctSourcesThreshold(),
		signatory:               ps,
		FileName:                filename,
	}

	chartDigest, err := Digest(bytes.NewBuffer(archiveData))
	if err != nil {
		return nil, err
	}

	data := provData
	for {
		block, rest := clearsign.Decode(data)
		if block == nil {
			break
		}
		data = rest

		j := SignatureJudgment{Block: len(res.Judgments) + 1}

		sigBody, readErr := io.ReadAll(block.ArmoredSignature.Body)
		if readErr != nil {
			j.Reason = reasonInvalidSignature
			j.Basis = fmt.Sprintf("failed to read signature packet: %s", readErr)
			j.IssuerKeyID = peekIssuerKeyID(sigBody)
			res.Judgments = append(res.Judgments, j)
			continue
		}
		j.IssuerKeyID = peekIssuerKeyID(sigBody)

		sig, signer, verr := openpgp.VerifyDetachedSignature(
			ps.KeyRing,
			bytes.NewReader(block.Bytes),
			bytes.NewReader(sigBody),
			&defaultPGPConfig,
		)
		switch {
		case verr == nil:
			j.CryptographicallyValid = true
			j.KnownSigner = true
			j.SignedByEntity(signer)
			j.Sources = append([]string(nil), ps.keySources[fingerprintOf(signer)]...)
			if sig != nil {
				j.Annotations = notationValues(sig)
			}
		case errors.Is(verr, pgperrors.ErrUnknownIssuer):
			j.Reason = reasonUnknownSigner
			j.Basis = "signing key not found in any counted key source"
			res.Judgments = append(res.Judgments, j)
			continue
		default:
			j.Reason = reasonInvalidSignature
			j.Basis = fmt.Sprintf("signature is cryptographically invalid: %s", verr)
			if e := ps.findByKeyID(j.IssuerKeyID); e != nil {
				j.KnownSigner = true
				j.SignedByEntity(e)
				j.Sources = append([]string(nil), ps.keySources[fingerprintOf(e)]...)
			}
			res.Judgments = append(res.Judgments, j)
			continue
		}

		// The signature is valid; now check that what it signs actually
		// attests the archive under verification.
		recorded, perr := digestForFile(block.Plaintext, filename)
		j.ChartDigest = "sha256:" + chartDigest
		switch {
		case perr != nil:
			j.DigestMatches = false
			j.Reason = reasonDigestMismatch
			j.RecordedDigest = ""
			j.Basis = fmt.Sprintf("valid signature, but %s", perr)
		case recorded != j.ChartDigest:
			j.DigestMatches = false
			j.Reason = reasonDigestMismatch
			j.RecordedDigest = recorded
			j.Basis = fmt.Sprintf("valid signature, but digest does not match: provenance records %s, chart is %s", recorded, j.ChartDigest)
		default:
			j.DigestMatches = true
			j.RecordedDigest = recorded
			ps.admit(&j)
		}

		res.Judgments = append(res.Judgments, j)
	}

	if len(res.Judgments) == 0 {
		return nil, errors.New("signature block not found")
	}

	ps.evaluate(res)
	return res, nil
}

// SignedByEntity fills identity/fingerprint fields from an entity.
func (j *SignatureJudgment) SignedByEntity(e *openpgp.Entity) {
	if e == nil {
		return
	}
	for name := range e.Identities {
		j.Identities = append(j.Identities, name)
	}
	sort.Strings(j.Identities)
	if e.PrimaryKey != nil {
		j.Fingerprint = fingerprintOf(e)
	}
}

// admit applies the effective admission rules to one cryptographically valid,
// digest-matching signature. Deny lists are evaluated first; an allow/deny
// conflict has already been rejected while building the effective policy, so
// ordering here can never be gamed through file order.
func (ps *PolicySignatory) admit(j *SignatureJudgment) {
	eff := ps.policy

	for _, r := range eff.identityDeny {
		if identityMatches(r.value, j.Identities) {
			j.reject(reasonDeniedIdentity, fmt.Sprintf(
				"identity matched deny list entry %q (from %s)", r.value, r.origin))
			return
		}
	}
	for _, r := range eff.fpDeny {
		if fingerprintMatches(r.value, j.Fingerprint) {
			j.reject(reasonDeniedFingerprint, fmt.Sprintf(
				"fingerprint matched deny list entry %q (from %s)", r.value, r.origin))
			return
		}
	}

	if len(eff.identityAllow) > 0 {
		matched := false
		for _, r := range eff.identityAllow {
			if identityMatches(r.value, j.Identities) {
				matched = true
				break
			}
		}
		if !matched {
			j.reject(reasonIdentityNotAllowed, fmt.Sprintf(
				"no identity of the signer is in the identity allow list %s (from %s)",
				formatRuleValues(eff.identityAllow), formatOrigins(eff.identityAllow)))
			return
		}
	}

	if len(eff.fpAllow) > 0 && !anyFingerprintRule(eff.fpAllow, j.Fingerprint) {
		j.reject(reasonFingerprintNotAllow, fmt.Sprintf(
			"fingerprint %s is not in the fingerprint allow list %s (from %s)",
			j.Fingerprint, formatRuleValues(eff.fpAllow), formatOrigins(eff.fpAllow)))
		return
	}

	for _, p := range eff.identityPatterns {
		if !slices.ContainsFunc(j.Identities, p.re.MatchString) {
			j.reject(reasonIdentityPattern, fmt.Sprintf(
				"no identity of the signer matches required identity pattern %q (from %s)", p.raw, p.origin))
			return
		}
	}
	for _, p := range eff.fpPatterns {
		if !p.re.MatchString(j.Fingerprint) {
			j.reject(reasonFingerprintPattern, fmt.Sprintf(
				"fingerprint %s does not match required fingerprint pattern %q (from %s)",
				j.Fingerprint, p.raw, p.origin))
			return
		}
	}

	for _, a := range eff.annotations {
		got, ok := j.Annotations[a.key]
		switch {
		case !ok:
			j.reject(reasonMissingAnnotation, fmt.Sprintf(
				"signature does not carry required annotation %q (from %s)", a.key, a.origin))
			return
		case a.value != "" && got != a.value:
			j.reject(reasonMissingAnnotation, fmt.Sprintf(
				"required annotation %q has value %q, expected %q (from %s)", a.key, got, a.value, a.origin))
			return
		}
	}

	j.Admitted = true
	j.Reason = reasonAdmitted
	j.Basis = "valid signature, digest matched, admitted by policy"
}

func (j *SignatureJudgment) reject(reason, basis string) {
	j.Admitted = false
	j.Reason = reason
	j.Basis = basis
}

// evaluate applies the layered gates and fixes the final status, message and
// counts.
func (ps *PolicySignatory) evaluate(res *PolicyVerification) {
	var mismatches, rejected []*SignatureJudgment
	seenFP := map[string]int{} // fingerprint -> first block number

	for i := range res.Judgments {
		j := &res.Judgments[i]
		switch {
		case j.CryptographicallyValid && !j.DigestMatches:
			mismatches = append(mismatches, j)
		case j.CryptographicallyValid && j.DigestMatches && !j.Admitted:
			rejected = append(rejected, j)
		case j.CryptographicallyValid && j.DigestMatches && j.Admitted:
			if first, dup := seenFP[j.Fingerprint]; dup {
				j.Admitted = false
				j.Reason = reasonDuplicate
				j.Basis = fmt.Sprintf("same key already provided a valid signature in block %d; counted once", first)
			} else {
				seenFP[j.Fingerprint] = j.Block
			}
		}
	}

	// Gate 0 (integrity): a valid signature over non-matching content fails
	// before any admission or counting decision.
	if len(mismatches) > 0 {
		res.Status = StatusDigestMismatch
		res.Message = firstBasis(mismatches)
		return
	}

	// Gate 1 (admission hard veto): a verifiable signer rejected by policy
	// fails even if other signatures are missing.
	if len(rejected) > 0 {
		res.Status = StatusSignerForbidden
		var parts []string
		for _, j := range rejected {
			parts = append(parts, fmt.Sprintf("signer %s rejected: %s", formatIdentities(j), j.Basis))
		}
		res.Message = strings.Join(parts, "; ")
		return
	}

	// Count distinct admitted keys and the sources they cover.
	sourceSet := map[string]bool{}
	for i := range res.Judgments {
		j := &res.Judgments[i]
		if j.Reason == reasonAdmitted {
			res.ValidSignatures++
			if res.SignedBy == nil {
				res.SignedBy = ps.entityForFingerprint(j.Fingerprint)
				res.FileHash = j.RecordedDigest
			}
			for _, s := range j.Sources {
				sourceSet[s] = true
			}
		}
	}
	res.DistinctSources = sortedKeys(sourceSet)

	// Gate 2: nothing verifiable at all is an unknown-signer outcome, kept
	// separate from "too few" signatures.
	if res.ValidSignatures == 0 {
		res.Status = StatusUnknownSigner
		res.Message = unknownSignerMessage(res.Judgments)
		return
	}

	// Gate 3: quantity gates.
	var unmet []string
	if res.ValidSignatures < res.RequiredValidSignatures {
		unmet = append(unmet, fmt.Sprintf("insufficient valid signatures: found %d (%s), required %d",
			res.ValidSignatures, formatAdmittedIdentities(res.Judgments), res.RequiredValidSignatures))
	}
	if res.RequiredDistinctSources > 0 && len(res.DistinctSources) < res.RequiredDistinctSources {
		unmet = append(unmet, fmt.Sprintf("insufficient distinct key sources: found %d (%s), required %d",
			len(res.DistinctSources), strings.Join(res.DistinctSources, ", "), res.RequiredDistinctSources))
	}
	if len(unmet) > 0 {
		res.Status = StatusInsufficientSignatures
		res.Message = strings.Join(unmet, "; ")
		return
	}

	res.Status = StatusVerified
	res.Message = fmt.Sprintf("verification passed: %d valid signature(s) from %d distinct source(s)",
		res.ValidSignatures, len(res.DistinctSources))
}

// Report renders the effective policy, source accounting, per-signature
// judgments and the final result line.
func (res *PolicyVerification) Report() string {
	var b strings.Builder
	b.WriteString("Verification Policy:\n")
	b.WriteString(res.signatory.policy.describe())
	b.WriteString(res.signatory.describeSourceAccounting())

	b.WriteString("Judged Signatures:\n")
	for i := range res.Judgments {
		b.WriteString(renderJudgment(&res.Judgments[i]))
	}

	final := "verification passed"
	if res.Status != StatusVerified {
		final = fmt.Sprintf("verification FAILED (%s): %s", res.Status, res.Message)
	}
	fmt.Fprintf(&b, "Result: %s\n", final)
	return b.String()
}

func renderJudgment(j *SignatureJudgment) string {
	var b strings.Builder
	if j.KnownSigner {
		fmt.Fprintf(&b, "  %d. %s\n", j.Block, formatIdentities(j))
		fmt.Fprintf(&b, "     Fingerprint: %s\n", j.Fingerprint)
		if len(j.Sources) > 0 {
			fmt.Fprintf(&b, "     Key Sources: %s\n", strings.Join(j.Sources, ", "))
		}
	} else {
		who := "unknown signer"
		if j.IssuerKeyID != "" {
			who = "unknown signer (issuer key 0x" + j.IssuerKeyID + ")"
		}
		fmt.Fprintf(&b, "  %d. %s\n", j.Block, who)
	}

	switch {
	case j.CryptographicallyValid && j.DigestMatches:
		b.WriteString("     Signature: cryptographically valid; chart digest matched\n")
	case j.CryptographicallyValid:
		b.WriteString("     Signature: cryptographically valid; chart digest NOT matched\n")
		if j.RecordedDigest != "" {
			fmt.Fprintf(&b, "     Recorded Digest: %s\n", j.RecordedDigest)
		}
		fmt.Fprintf(&b, "     Chart Digest: %s\n", j.ChartDigest)
	default:
		b.WriteString("     Signature: not verified\n")
	}

	if len(j.Annotations) > 0 {
		keys := make([]string, 0, len(j.Annotations))
		for k := range j.Annotations {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, k+"="+j.Annotations[k])
		}
		fmt.Fprintf(&b, "     Annotations: %s\n", strings.Join(parts, ", "))
	}

	verdict := j.Basis
	if j.Reason == reasonAdmitted {
		verdict = "admitted (" + j.Basis + ")"
	}
	fmt.Fprintf(&b, "     Verdict: %s\n", verdict)
	return b.String()
}

// FailureError returns nil for a passing verification, otherwise an error
// carrying the failure message and the full policy/judgment report.
func (res *PolicyVerification) FailureError() error {
	if res.Status == StatusVerified {
		return nil
	}
	return fmt.Errorf("verification failed: %s\n%s", res.Message, res.Report())
}

// digestForFile extracts the recorded digest for filename from a signed
// message block.
func digestForFile(plaintext []byte, filename string) (string, error) {
	sums, err := parseMessageBlock(plaintext)
	if err != nil {
		return "", fmt.Errorf("provenance message block is invalid: %w", err)
	}
	sha, ok := sums.Files[filename]
	if !ok {
		return "", fmt.Errorf("provenance does not contain a digest for file %q", filename)
	}
	return sha, nil
}

// peekIssuerKeyID extracts the issuer key id from a detached signature packet
// stream without requiring the signer key.
func peekIssuerKeyID(body []byte) string {
	r := packet.NewReader(bytes.NewReader(body))
	for {
		p, err := r.Next()
		if err != nil {
			return ""
		}
		if sig, ok := p.(*packet.Signature); ok && sig.IssuerKeyId != nil {
			return fmt.Sprintf("%016X", *sig.IssuerKeyId)
		}
	}
}

// notationValues collects the signature's notation data as key/value strings.
// The library-internal signature salt notation is omitted: it is randomized
// signing machinery, not a signer assertion policies should match on.
func notationValues(sig *packet.Signature) map[string]string {
	out := map[string]string{}
	for _, n := range sig.Notations {
		if n.Name == packet.SaltNotationName {
			continue
		}
		v := string(n.Value)
		if existing, ok := out[n.Name]; ok {
			out[n.Name] = existing + "," + v
		} else {
			out[n.Name] = v
		}
	}
	return out
}

// findByKeyID returns the entity whose primary key id matches the given hex
// id, used only to label signatures that did not verify.
func (ps *PolicySignatory) findByKeyID(hexID string) *openpgp.Entity {
	if hexID == "" {
		return nil
	}
	for _, e := range ps.KeyRing {
		if e != nil && e.PrimaryKey != nil && fmt.Sprintf("%016X", e.PrimaryKey.KeyId) == hexID {
			return e
		}
	}
	return nil
}

// entityForFingerprint returns the merged entity for a fingerprint, if any.
func (ps *PolicySignatory) entityForFingerprint(fp string) *openpgp.Entity {
	for _, e := range ps.KeyRing {
		if fingerprintOf(e) == fp {
			return e
		}
	}
	return nil
}

// identityMatches reports whether a list entry matches any identity. An entry
// is matched exactly or as a glob against the full identity or against its
// email component (the part between angle brackets).
func identityMatches(entry string, identities []string) bool {
	for _, id := range identities {
		if entry == id || globMatch(entry, id) {
			return true
		}
		if email := emailOf(id); email != "" && (entry == email || globMatch(entry, email)) {
			return true
		}
	}
	return false
}

// fingerprintMatches reports whether a fingerprint list entry matches the
// given fingerprint. A shorter entry is accepted as a suffix, following the
// GnuPG key-id convention.
func fingerprintMatches(entry, fingerprint string) bool {
	n := normalizeFingerprint(entry)
	if n == "" {
		return false
	}
	return n == fingerprint || strings.HasSuffix(fingerprint, n)
}

func anyFingerprintRule(rules []taggedString, fp string) bool {
	for _, r := range rules {
		if fingerprintMatches(r.value, fp) {
			return true
		}
	}
	return false
}

// globMatch applies path.Match semantics, falling back to an exact comparison
// for malformed glob patterns.
func globMatch(pattern, value string) bool {
	if matched, err := path.Match(pattern, value); err == nil {
		return matched
	}
	return pattern == value
}

// emailOf extracts the address between angle brackets.
func emailOf(identity string) string {
	i := strings.IndexByte(identity, '<')
	j := strings.IndexByte(identity, '>')
	if i >= 0 && j > i {
		return identity[i+1 : j]
	}
	return ""
}

func formatIdentities(j *SignatureJudgment) string {
	switch len(j.Identities) {
	case 0:
		return "unknown"
	case 1:
		return j.Identities[0]
	default:
		return strings.Join(j.Identities, " / ")
	}
}

func formatAdmittedIdentities(judgments []SignatureJudgment) string {
	var ids []string
	for i := range judgments {
		if judgments[i].Reason == reasonAdmitted {
			ids = append(ids, formatIdentities(&judgments[i]))
		}
	}
	return strings.Join(ids, ", ")
}

func firstBasis(js []*SignatureJudgment) string {
	if len(js) == 0 {
		return ""
	}
	return js[0].Basis
}

func unknownSignerMessage(js []SignatureJudgment) string {
	var unknown, invalid int
	for i := range js {
		switch js[i].Reason {
		case reasonUnknownSigner:
			unknown++
		default:
			invalid++
		}
	}
	parts := []string{"no signature could be verified against the counted key sources"}
	if unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d signature(s) by unknown signers", unknown))
	}
	if invalid > 0 {
		parts = append(parts, fmt.Sprintf("%d signature(s) cryptographically invalid", invalid))
	}
	return strings.Join(parts, "; ")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func formatRuleValues(rules []taggedString) string {
	values := make([]string, len(rules))
	for i, r := range rules {
		values[i] = r.value
	}
	return "[" + strings.Join(values, ", ") + "]"
}

func formatOrigins(rules []taggedString) string {
	return strings.Join(originsOf(rules), ", ")
}
