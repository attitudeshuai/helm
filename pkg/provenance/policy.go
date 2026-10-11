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
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// OriginCommandLine is the origin label attached to policy values supplied on
// the command line, as opposed to values loaded from a policy file (whose
// origin label is the file path).
const OriginCommandLine = "command-line"

// KeySource declares one place verification keys are loaded from. Path may
// point at a single keyring file (binary packet stream, GnuPG keybox or
// ASCII-armored) or at a directory whose regular files are each read as a
// keyring. Name is optional and defaults to Path; it is how the source is
// referred to in verification output and in the distinct-source count.
type KeySource struct {
	Name string `yaml:"name,omitempty"`
	Path string `yaml:"path"`
}

// Admission is one identity- or fingerprint-based admission rule set.
//
//   - Allow: only values matched by this list are admitted. An empty list
//     imposes no allow restriction.
//   - Deny: matched values are always rejected.
//   - RequiredPatterns: regular expressions that every admitted value must
//     match (all patterns are required).
type Admission struct {
	Allow            []string `yaml:"allow,omitempty"`
	Deny             []string `yaml:"deny,omitempty"`
	RequiredPatterns []string `yaml:"requiredPatterns,omitempty"`
}

// Policy is the declarative verification policy.
//
// A policy references several key sources, constrains which signing
// identities/fingerprints are admitted, and can require more than one valid
// signature, optionally spread across several distinct key sources.
type Policy struct {
	// KeySources are the keyring files and key directories merged for
	// verification.
	KeySources []KeySource `yaml:"keySources,omitempty"`
	// Identities admits or rejects signing identities.
	Identities Admission `yaml:"identities,omitempty"`
	// Fingerprints admits or rejects primary key fingerprints.
	Fingerprints Admission `yaml:"fingerprints,omitempty"`
	// MinValidSignatures requires at least this many distinct keys to have
	// produced valid, digest-matching, admitted signatures. Zero means the
	// default of one.
	MinValidSignatures int `yaml:"minValidSignatures,omitempty"`
	// MinDistinctSources requires the valid signatures to cover at least this
	// many distinct key sources. Zero disables the requirement.
	MinDistinctSources int `yaml:"minDistinctSources,omitempty"`
	// RequiredAnnotations only admits signatures carrying all of the given
	// OpenPGP notation data subpackets (name/value); an empty value only
	// requires the notation to be present.
	RequiredAnnotations map[string]string `yaml:"requiredAnnotations,omitempty"`
}

// PolicyOverrides carries command-line supplied policy values. nil slices and
// nil pointers leave the corresponding policy-file values in place; an
// initialized (including empty) slice explicitly replaces them, mirroring
// command-line override precedence.
type PolicyOverrides struct {
	// ExtraKeyrings adds command-line keyring files.
	ExtraKeyrings []string
	// KeyDirs adds command-line key directories.
	KeyDirs []string
	// Identities and Fingerprints override the policy-file admission lists.
	Identities   Admission
	Fingerprints Admission
	// MinValidSignatures and MinDistinctSources, when non-nil, override the
	// policy-file values.
	MinValidSignatures *int
	MinDistinctSources *int
	// RequiredAnnotations, when non-nil, replaces policy-file annotations.
	RequiredAnnotations map[string]string
}

// taggedString is an admission-list entry carrying the origin (policy file
// path or OriginCommandLine) it came from.
type taggedString struct {
	value  string
	origin string
}

// taggedKV is a required annotation entry with its origin.
type taggedKV struct {
	key    string
	value  string
	origin string
}

// compiledPattern is a required regular expression with its raw form and
// origin for reporting.
type compiledPattern struct {
	raw    string
	origin string
	re     *regexp.Regexp
}

// taggedInt is a scalar policy value carrying the origin of its last writer.
type taggedInt struct {
	value  int
	origin string
	set    bool
}

// effectiveSource is a key source after dedup, carrying every origin it was
// declared in.
type effectiveSource struct {
	name    string
	path    string
	dir     bool
	origins []string
}

// EffectivePolicy is the result of merging policy files and command-line
// overrides. Every effective value records where it came from so verification
// output can explain item by item what is in force.
type EffectivePolicy struct {
	sources []effectiveSource

	identityAllow []taggedString
	identityDeny  []taggedString
	fpAllow       []taggedString
	fpDeny        []taggedString

	identityPatterns []compiledPattern
	fpPatterns       []compiledPattern

	minValid   taggedInt
	minSources taggedInt

	annotations []taggedKV

	// notes records supersession decisions, e.g. a policy-file value replaced
	// by a later file or by the command line.
	notes []string
}

// LoadPolicy reads and parses one policy file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read verification policy %s: %w", path, err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse verification policy %s: %w", path, err)
	}
	return &p, nil
}

// BuildEffectivePolicy loads the given policy files in order, merges them and
// applies the command-line overrides. The primaryKeyring, when non-empty, is
// prepended as a command-line-origin key source. Compilation of patterns and
// allow/deny conflict detection happens here and fails closed.
func BuildEffectivePolicy(primaryKeyring string, policyFiles []string, ov *PolicyOverrides) (*EffectivePolicy, error) {
	eff := &EffectivePolicy{}

	if primaryKeyring != "" {
		eff.addSource(KeySource{Path: primaryKeyring}, OriginCommandLine)
	}

	for _, path := range policyFiles {
		p, err := LoadPolicy(path)
		if err != nil {
			return nil, err
		}
		eff.merge(p, path)
	}

	if ov != nil {
		eff.applyOverrides(ov)
	}

	if err := eff.compilePatterns(); err != nil {
		return nil, err
	}
	if err := eff.checkConflicts(); err != nil {
		return nil, err
	}
	return eff, nil
}

// merge folds one policy file (labeled origin) into the effective policy.
// Lists union in file order; scalars use last-writer-wins; annotations replace
// per key.
func (eff *EffectivePolicy) merge(p *Policy, origin string) {
	for _, s := range p.KeySources {
		eff.addSource(s, origin)
	}
	eff.identityAllow = mergeTaggedStrings(eff.identityAllow, p.Identities.Allow, origin)
	eff.identityDeny = mergeTaggedStrings(eff.identityDeny, p.Identities.Deny, origin)
	eff.fpAllow = mergeTaggedStrings(eff.fpAllow, p.Fingerprints.Allow, origin)
	eff.fpDeny = mergeTaggedStrings(eff.fpDeny, p.Fingerprints.Deny, origin)

	eff.identityPatterns = mergeRawPatterns(eff.identityPatterns, p.Identities.RequiredPatterns, origin)
	eff.fpPatterns = mergeRawPatterns(eff.fpPatterns, p.Fingerprints.RequiredPatterns, origin)

	if p.MinValidSignatures > 0 {
		eff.minValid = overrideInt(eff.minValid, p.MinValidSignatures, origin, "minimum valid signatures", &eff.notes)
	}
	if p.MinDistinctSources > 0 {
		eff.minSources = overrideInt(eff.minSources, p.MinDistinctSources, origin, "minimum distinct sources", &eff.notes)
	}

	for k, v := range p.RequiredAnnotations {
		eff.annotations = putAnnotation(eff.annotations, taggedKV{key: k, value: v, origin: origin}, &eff.notes)
	}
}

// applyOverrides folds in command-line values, which take precedence over
// every policy-file value.
func (eff *EffectivePolicy) applyOverrides(ov *PolicyOverrides) {
	for _, p := range ov.ExtraKeyrings {
		eff.addSource(KeySource{Path: p}, OriginCommandLine)
	}
	for _, d := range ov.KeyDirs {
		eff.addSource(KeySource{Path: d}, OriginCommandLine)
	}

	replaceStringList := func(current []taggedString, field string, next []string) []taggedString {
		if next == nil {
			return current
		}
		if len(current) > 0 {
			origins := originsOf(current)
			eff.notes = append(eff.notes, fmt.Sprintf(
				"%s from %s %s superseded by %s",
				field, joinQuoted(origins), wasWere(len(origins)), OriginCommandLine))
		}
		return mergeTaggedStrings(nil, next, OriginCommandLine)
	}

	eff.identityAllow = replaceStringList(eff.identityAllow, "identity allow list", ov.Identities.Allow)
	eff.identityDeny = replaceStringList(eff.identityDeny, "identity deny list", ov.Identities.Deny)
	eff.fpAllow = replaceStringList(eff.fpAllow, "fingerprint allow list", ov.Fingerprints.Allow)
	eff.fpDeny = replaceStringList(eff.fpDeny, "fingerprint deny list", ov.Fingerprints.Deny)

	replacePatternList := func(current []compiledPattern, field string, next []string) []compiledPattern {
		if next == nil {
			return current
		}
		if len(current) > 0 {
			origins := patternOrigins(current)
			eff.notes = append(eff.notes, fmt.Sprintf(
				"%s from %s %s superseded by %s",
				field, joinQuoted(origins), wasWere(len(origins)), OriginCommandLine))
		}
		return mergeRawPatterns(nil, next, OriginCommandLine)
	}

	eff.identityPatterns = replacePatternList(eff.identityPatterns, "identity required patterns", ov.Identities.RequiredPatterns)
	eff.fpPatterns = replacePatternList(eff.fpPatterns, "fingerprint required patterns", ov.Fingerprints.RequiredPatterns)

	if ov.MinValidSignatures != nil {
		eff.minValid = overrideInt(eff.minValid, *ov.MinValidSignatures, OriginCommandLine, "minimum valid signatures", &eff.notes)
	}
	if ov.MinDistinctSources != nil {
		eff.minSources = overrideInt(eff.minSources, *ov.MinDistinctSources, OriginCommandLine, "minimum distinct sources", &eff.notes)
	}

	if ov.RequiredAnnotations != nil {
		if len(eff.annotations) > 0 {
			origins := annotationOrigins(eff.annotations)
			eff.notes = append(eff.notes, fmt.Sprintf(
				"required annotations from %s %s superseded by %s",
				joinQuoted(origins), wasWere(len(origins)), OriginCommandLine))
			eff.annotations = nil
		}
		// Sort so command-line override output is stable.
		keys := make([]string, 0, len(ov.RequiredAnnotations))
		for k := range ov.RequiredAnnotations {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			eff.annotations = putAnnotation(eff.annotations, taggedKV{key: k, value: ov.RequiredAnnotations[k], origin: OriginCommandLine}, &eff.notes)
		}
	}
}

// addSource records a key source. It is merged with an earlier source when it
// shares the effective name OR the same path, so the same file can never be
// counted as two distinct sources.
func (eff *EffectivePolicy) addSource(s KeySource, origin string) {
	name := s.Name
	if name == "" {
		name = s.Path
	}
	for i := range eff.sources {
		cur := &eff.sources[i]
		if cur.name != name && cur.path != s.Path {
			continue
		}
		if !slices.Contains(cur.origins, origin) {
			cur.origins = append(cur.origins, origin)
		}
		if cur.path != s.Path {
			eff.notes = append(eff.notes, fmt.Sprintf(
				"key source %q declared with conflicting paths %q (%s) and %q (%s); using %q",
				cur.name, cur.path, joinQuoted(cur.origins), s.Path, origin, cur.path))
		}
		return
	}
	eff.sources = append(eff.sources, effectiveSource{
		name:    name,
		path:    s.Path,
		origins: []string{origin},
	})
}

// compilePatterns compiles every required regular expression.
func (eff *EffectivePolicy) compilePatterns() error {
	compile := func(raw []compiledPattern, kind string) ([]compiledPattern, error) {
		for i := range raw {
			re, err := regexp.Compile(raw[i].raw)
			if err != nil {
				return nil, fmt.Errorf("invalid %s pattern %q (from %s): %w", kind, raw[i].raw, raw[i].origin, err)
			}
			raw[i].re = re
		}
		return raw, nil
	}
	var err error
	if eff.identityPatterns, err = compile(eff.identityPatterns, "identity"); err != nil {
		return err
	}
	eff.fpPatterns, err = compile(eff.fpPatterns, "fingerprint")
	return err
}

// PolicyConflictError reports one value present in both an allow and a deny
// list. Conflicts always fail closed and never depend on file order.
type PolicyConflictError struct {
	Kind  string // "identity" or "fingerprint"
	Value string
	Allow string // origin of the allow entry
	Deny  string // origin of the deny entry
}

func (e *PolicyConflictError) Error() string {
	return fmt.Sprintf(
		"verification policy conflict: %s %q is present in both the allow list (from %s) and the deny list (from %s); refusing to pick one by file order",
		e.Kind, e.Value, e.Allow, e.Deny)
}

// checkConflicts fails when the same value is in both an allow and a deny
// list. Fingerprints are compared in normalized form; the reported value is
// the normalized one.
func (eff *EffectivePolicy) checkConflicts() error {
	for _, a := range eff.identityAllow {
		for _, d := range eff.identityDeny {
			if a.value == d.value {
				return &PolicyConflictError{Kind: "identity", Value: a.value, Allow: a.origin, Deny: d.origin}
			}
		}
	}
	denyFP := map[string]string{}
	for _, d := range eff.fpDeny {
		denyFP[normalizeFingerprint(d.value)] = d.origin
	}
	for _, a := range eff.fpAllow {
		n := normalizeFingerprint(a.value)
		if origin, ok := denyFP[n]; ok {
			return &PolicyConflictError{Kind: "fingerprint", Value: n, Allow: a.origin, Deny: origin}
		}
	}
	return nil
}

// minValidSignatures returns the effective threshold, defaulting to one when a
// policy is in force.
func (eff *EffectivePolicy) minValidThreshold() int {
	if eff.minValid.set && eff.minValid.value > 0 {
		return eff.minValid.value
	}
	return 1
}

// minDistinctSourcesThreshold returns the effective distinct-source threshold.
func (eff *EffectivePolicy) minDistinctSourcesThreshold() int {
	return eff.minSources.value
}

// describe renders the effective policy, item by item, with origins and
// supersession notes. Only in-force fields are rendered.
func (eff *EffectivePolicy) describe() string {
	var b strings.Builder

	for i := range eff.sources {
		s := &eff.sources[i]
		fmt.Fprintf(&b, "  Key Source: %s (%s; from %s)\n", s.name, s.path, joinQuoted(s.origins))
	}
	for _, ts := range eff.identityAllow {
		fmt.Fprintf(&b, "  Identity Allow: %s (from %s)\n", ts.value, ts.origin)
	}
	for _, ts := range eff.identityDeny {
		fmt.Fprintf(&b, "  Identity Deny: %s (from %s)\n", ts.value, ts.origin)
	}
	for _, p := range eff.identityPatterns {
		fmt.Fprintf(&b, "  Identity Required Pattern: %s (from %s)\n", p.raw, p.origin)
	}
	for _, ts := range eff.fpAllow {
		fmt.Fprintf(&b, "  Fingerprint Allow: %s (from %s)\n", ts.value, ts.origin)
	}
	for _, ts := range eff.fpDeny {
		fmt.Fprintf(&b, "  Fingerprint Deny: %s (from %s)\n", ts.value, ts.origin)
	}
	for _, p := range eff.fpPatterns {
		fmt.Fprintf(&b, "  Fingerprint Required Pattern: %s (from %s)\n", p.raw, p.origin)
	}
	if eff.minValid.set {
		fmt.Fprintf(&b, "  Minimum Valid Signatures: %d (from %s)\n", eff.minValid.value, eff.minValid.origin)
	}
	if eff.minSources.set {
		fmt.Fprintf(&b, "  Minimum Distinct Sources: %d (from %s)\n", eff.minSources.value, eff.minSources.origin)
	}
	for _, a := range eff.annotations {
		fmt.Fprintf(&b, "  Required Annotation: %s=%s (from %s)\n", a.key, a.value, a.origin)
	}
	for _, note := range eff.notes {
		fmt.Fprintf(&b, "  Policy Merge: %s\n", note)
	}
	return b.String()
}

// mergeTaggedStrings appends new tagged values, dropping duplicates and
// keeping the first origin for an identical value.
func mergeTaggedStrings(existing []taggedString, values []string, origin string) []taggedString {
	for _, v := range values {
		duplicate := false
		for _, e := range existing {
			if e.value == v {
				duplicate = true
				break
			}
		}
		if !duplicate {
			existing = append(existing, taggedString{value: v, origin: origin})
		}
	}
	return existing
}

// mergeRawPatterns appends required patterns; compilation happens later.
func mergeRawPatterns(existing []compiledPattern, patterns []string, origin string) []compiledPattern {
	for _, p := range patterns {
		duplicate := false
		for _, e := range existing {
			if e.raw == p {
				duplicate = true
				break
			}
		}
		if !duplicate {
			existing = append(existing, compiledPattern{raw: p, origin: origin})
		}
	}
	return existing
}

// overrideInt applies last-writer-wins to a scalar and records the
// supersession.
func overrideInt(current taggedInt, next int, origin, field string, notes *[]string) taggedInt {
	if current.set {
		*notes = append(*notes, fmt.Sprintf("%s: %d (from %s) superseded by %d (from %s)",
			field, current.value, current.origin, next, origin))
	}
	return taggedInt{value: next, origin: origin, set: true}
}

// putAnnotation inserts or replaces one annotation entry.
func putAnnotation(existing []taggedKV, next taggedKV, notes *[]string) []taggedKV {
	for i, e := range existing {
		if e.key == next.key {
			*notes = append(*notes, fmt.Sprintf("required annotation %q: %q (from %s) superseded by %q (from %s)",
				e.key, e.value, e.origin, next.value, next.origin))
			existing[i] = next
			return existing
		}
	}
	return append(existing, next)
}

func originsOf(list []taggedString) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range list {
		if !seen[t.origin] {
			seen[t.origin] = true
			out = append(out, t.origin)
		}
	}
	sort.Strings(out)
	return out
}

func patternOrigins(list []compiledPattern) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range list {
		if !seen[p.origin] {
			seen[p.origin] = true
			out = append(out, p.origin)
		}
	}
	sort.Strings(out)
	return out
}

func annotationOrigins(list []taggedKV) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range list {
		seen[a.origin] = true
	}
	for o := range seen {
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

// joinQuoted renders origin labels for human-readable output. Unlike fmt's
// %q, it does not escape backslashes (which would mangle Windows paths).
func joinQuoted(values []string) string {
	return `"` + strings.Join(values, `", "`) + `"`
}

func wasWere(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}

// normalizeFingerprint canonicalizes a user-supplied fingerprint: an optional
// 0x prefix, colons and whitespace are stripped, and the result is upper
// cased.
func normalizeFingerprint(in string) string {
	s := strings.TrimSpace(in)
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	s = strings.NewReplacer(":", "", " ", "", "\t", "").Replace(s)
	return strings.ToUpper(s)
}
