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
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	"helm.sh/helm/v4/pkg/helmpath"
)

// SourceType identifies the kind of source that contributed a setting value.
type SourceType string

const (
	// SourceFlag is a value supplied on the command line.
	SourceFlag SourceType = "flag"
	// SourceEnv is a value supplied through a direct environment variable.
	SourceEnv SourceType = "env"
	// SourcePath is a value supplied through a path helper variable
	// (HELM_*_HOME takes precedence over the XDG_*_HOME variables).
	SourcePath SourceType = "path"
	// SourceKubeconfig is a value taken from the current kubeconfig context.
	SourceKubeconfig SourceType = "kubeconfig"
	// SourceDefault is the built-in default value of a setting.
	SourceDefault SourceType = "default"
)

// String returns a human readable description of the source type.
func (t SourceType) String() string {
	switch t {
	case SourceFlag:
		return "command-line flag"
	case SourceEnv:
		return "environment variable"
	case SourcePath:
		return "path variable"
	case SourceKubeconfig:
		return "kubeconfig context"
	case SourceDefault:
		return "built-in default"
	default:
		return string(t)
	}
}

// ValueSource describes one value observed for a setting while resolving the
// effective value.
type ValueSource struct {
	// Type identifies the kind of source.
	Type SourceType
	// Location pinpoints where the value came from, e.g. "--namespace",
	// "HELM_QPS", `kubeconfig context "my-context"` or "default" for the
	// built-in default.
	Location string
	// RawValue is the value as it was provided before normalization. It is
	// redacted for credential settings.
	RawValue string
	// Value is the normalized value for this source. It is redacted for
	// credential settings.
	Value string
	// External reports whether the value came from outside the command line,
	// i.e. an environment variable or a path variable. Only environment
	// variables and path variables are marked external.
	External bool
	// Invalid describes why RawValue could not be parsed. Empty when the
	// value is well formed. Invalid values never become effective.
	Invalid string
	// ReadError describes why the source itself could not be read. Other
	// setting keys are not affected by such a failure.
	ReadError string
	// Winning marks the source that provides the effective value.
	Winning bool
	// ShadowReason explains why the value did not take effect when Winning is
	// false.
	ShadowReason string
}

// ConflictValue groups the locations at which one distinct value was observed.
type ConflictValue struct {
	// Value is one of the distinct values observed for a setting. It is
	// redacted for credential settings.
	Value string
	// Effective marks the value that actually takes effect.
	Effective bool
	// Locations lists the sources that provided this value, in precedence
	// order.
	Locations []ValueSource
}

// Conflict describes a setting for which multiple sources provided different
// values.
type Conflict struct {
	// Key is the setting key.
	Key string
	// Values lists the distinct observed values, in precedence order.
	Values []ConflictValue
}

// Diagnostic describes a setting value whose format or semantics are invalid.
type Diagnostic struct {
	// Key is the setting key.
	Key string
	// Source identifies the kind of source holding the invalid value.
	Source SourceType
	// Location pinpoints the source, e.g. the environment variable or flag name.
	Location string
	// RawValue is the invalid value as provided. It is redacted for
	// credential settings.
	RawValue string
	// Expected describes the expected format or semantic constraint.
	Expected string
	// Reason describes why the value is invalid.
	Reason string
}

// String renders the diagnostic as a single human readable line.
func (d Diagnostic) String() string {
	return fmt.Sprintf("%s: invalid value %q from %s %s: %s (expected %s)",
		d.Key, d.RawValue, d.Source, d.Location, d.Reason, d.Expected)
}

// SourceReadError reports that one source of a setting could not be read.
type SourceReadError struct {
	// Key is the setting key.
	Key string
	// Source identifies the kind of source that failed to load.
	Source SourceType
	// Location pinpoints the source.
	Location string
	// Err describes the read failure.
	Err string
}

// SettingInfo describes the resolution of one setting key.
type SettingInfo struct {
	// Key is the canonical setting key name.
	Key string
	// Value is the value actually used by the command. Credential values are
	// redacted.
	Value string
	// Sensitive marks credential settings whose raw values must not be
	// displayed.
	Sensitive bool
	// External reports whether the effective value came from an environment
	// variable or a path variable.
	External bool
	// Sources lists every value observed while resolving the key, in
	// precedence order. The winning source is marked.
	Sources []ValueSource
}

// Report is the read-only provenance report for the effective CLI settings.
type Report struct {
	// Settings lists every setting key, sorted by name.
	Settings []SettingInfo
	// Unset lists keys that are only provided by the built-in default, i.e.
	// no flag, environment variable, path variable or kubeconfig context set
	// them.
	Unset []string
	// Conflicts lists keys for which multiple sources provided different
	// values.
	Conflicts []Conflict
	// Invalid lists values whose format or semantics are invalid.
	Invalid []Diagnostic
	// ReadErrors lists sources that could not be read.
	ReadErrors []SourceReadError
}

// redactedValue replaces non-empty credential values in reports.
const redactedValue = "<redacted>"

type valueKind int

const (
	kindString valueKind = iota
	kindBool
	kindInt
	kindFloat
	kindCSV
	kindColor
)

// keyDef describes a single CLI setting key.
type keyDef struct {
	name        string
	kind        valueKind
	sensitive   bool
	flags       []string
	expected    string
	nonnegative bool
}

// candidate is an un-resolved observed source value.
type candidate struct {
	typ       SourceType
	location  string
	raw       string
	value     string
	external  bool
	invalid   string
	readError string
}

// provenance collects source observations gathered while building EnvSettings
// and assembles the provenance report once flags have been parsed.
type provenance struct {
	defs    map[string]*keyDef
	order   []*keyDef
	found   map[string][]candidate
	origins map[string]helmpath.PathOrigin
}

func newProvenance() *provenance {
	p := &provenance{
		defs:    map[string]*keyDef{},
		found:   map[string][]candidate{},
		origins: map[string]helmpath.PathOrigin{},
	}
	add := func(d *keyDef) {
		p.defs[d.name] = d
		p.order = append(p.order, d)
	}
	add(&keyDef{name: "HELM_NAMESPACE", kind: kindString, flags: []string{"namespace"}})
	add(&keyDef{name: "HELM_DEBUG", kind: kindBool, flags: []string{"debug"}, expected: "a boolean (e.g. true or false)"})
	add(&keyDef{name: "HELM_MAX_HISTORY", kind: kindInt, expected: "an integer; 0 means unlimited", nonnegative: true})
	add(&keyDef{name: "KUBECONFIG", kind: kindString, flags: []string{"kubeconfig"}})
	add(&keyDef{name: "HELM_KUBECONTEXT", kind: kindString, flags: []string{"kube-context"}})
	add(&keyDef{name: "HELM_KUBETOKEN", kind: kindString, flags: []string{"kube-token"}, sensitive: true})
	add(&keyDef{name: "HELM_KUBEASUSER", kind: kindString, flags: []string{"kube-as-user"}})
	add(&keyDef{name: "HELM_KUBEASGROUPS", kind: kindCSV, flags: []string{"kube-as-group"}})
	add(&keyDef{name: "HELM_KUBEAPISERVER", kind: kindString, flags: []string{"kube-apiserver"}})
	add(&keyDef{name: "HELM_KUBECAFILE", kind: kindString, flags: []string{"kube-ca-file"}})
	add(&keyDef{name: "HELM_KUBEINSECURE_SKIP_TLS_VERIFY", kind: kindBool, flags: []string{"kube-insecure-skip-tls-verify"}, expected: "a boolean (e.g. true or false)"})
	add(&keyDef{name: "HELM_KUBETLS_SERVER_NAME", kind: kindString, flags: []string{"kube-tls-server-name"}})
	add(&keyDef{name: "HELM_PLUGINS", kind: kindString, expected: "a path"})
	add(&keyDef{name: "HELM_REGISTRY_CONFIG", kind: kindString, flags: []string{"registry-config"}, expected: "a path"})
	add(&keyDef{name: "HELM_REPOSITORY_CONFIG", kind: kindString, flags: []string{"repository-config"}, expected: "a path"})
	add(&keyDef{name: "HELM_REPOSITORY_CACHE", kind: kindString, flags: []string{"repository-cache"}, expected: "a path"})
	add(&keyDef{name: "HELM_CONTENT_CACHE", kind: kindString, flags: []string{"content-cache"}, expected: "a path"})
	add(&keyDef{name: "HELM_BURST_LIMIT", kind: kindInt, flags: []string{"burst-limit"}, expected: "an integer; -1 disables client-side throttling"})
	add(&keyDef{name: "HELM_QPS", kind: kindFloat, flags: []string{"qps"}, expected: "a floating-point number", nonnegative: true})
	add(&keyDef{name: "HELM_COLOR", kind: kindColor, flags: []string{"color", "colour"}, expected: "one of: never, auto, always"})
	add(&keyDef{name: "HELM_CACHE_HOME", kind: kindString, expected: "a path"})
	add(&keyDef{name: "HELM_CONFIG_HOME", kind: kindString, expected: "a path"})
	add(&keyDef{name: "HELM_DATA_HOME", kind: kindString, expected: "a path"})
	return p
}

// record appends an observed candidate for a key.
func (p *provenance) record(key string, c candidate) {
	p.found[key] = append(p.found[key], c)
}

// envString reads a direct string environment variable. An empty string is
// treated as unset, so only non-empty values count as a source hit.
func (p *provenance) envString(key, name string) string {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return ""
	}
	p.record(key, candidate{
		typ:      SourceEnv,
		location: name,
		raw:      raw,
		value:    raw,
		external: true,
	})
	return raw
}

// envPathString reads an environment variable holding a path. Values that are
// empty or consist solely of separators and whitespace are treated as unset
// so that no empty path is produced.
func (p *provenance) envPathString(key, name, def string) string {
	raw, ok := os.LookupEnv(name)
	if !ok || helmpath.IsBlankPath(raw) {
		return def
	}
	p.record(key, candidate{
		typ:      SourceEnv,
		location: name,
		raw:      raw,
		value:    raw,
		external: true,
	})
	return raw
}

// envBool reads a boolean environment variable, recording parse failures
// while keeping the fallback behavior for the effective value.
func (p *provenance) envBool(key, name string, def bool) bool {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def
	}
	c := candidate{typ: SourceEnv, location: name, raw: raw, external: true}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		c.invalid = err.Error()
		p.record(key, c)
		return def
	}
	c.value = strconv.FormatBool(v)
	p.record(key, c)
	return v
}

// envInt reads an integer environment variable, recording parse failures
// while keeping the fallback behavior for the effective value.
func (p *provenance) envInt(key, name string, def int) int {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def
	}
	c := candidate{typ: SourceEnv, location: name, raw: raw, external: true}
	v, err := strconv.Atoi(raw)
	if err != nil {
		c.invalid = err.Error()
		p.record(key, c)
		return def
	}
	c.value = strconv.Itoa(v)
	p.record(key, c)
	return v
}

// envFloat reads a float32 environment variable, recording parse failures
// while keeping the fallback behavior for the effective value.
func (p *provenance) envFloat(key, name string, def float32) float32 {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def
	}
	c := candidate{typ: SourceEnv, location: name, raw: raw, external: true}
	v, err := strconv.ParseFloat(raw, 32)
	if err != nil {
		c.invalid = err.Error()
		p.record(key, c)
		return def
	}
	c.value = formatFloat(float32(v))
	p.record(key, c)
	return float32(v)
}

// envCSV reads a comma delimited environment variable, mirroring the trimming
// rules of envCSV. An empty result is treated as unset.
func (p *provenance) envCSV(key, name string) []string {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return nil
	}
	trimmed := strings.Trim(raw, ", ")
	if trimmed == "" {
		return nil
	}
	values := strings.Split(trimmed, ",")
	p.record(key, candidate{
		typ:      SourceEnv,
		location: name,
		raw:      raw,
		value:    strings.Join(values, ","),
		external: true,
	})
	return values
}

// envColor resolves the color mode, recording both NO_COLOR (which takes
// precedence) and HELM_COLOR observations. HELM_COLOR is observed even when
// NO_COLOR wins, so a conflicting or invalid lower-precedence value stays
// visible. An invalid HELM_COLOR value falls back, silently unless strict
// mode is enabled.
func (p *provenance) envColor() string {
	noColorRaw, noColorSet := os.LookupEnv("NO_COLOR")
	helmRaw, helmSet := os.LookupEnv("HELM_COLOR")

	// Record candidates in precedence order.
	helmEffective := ""
	helmInvalid := ""
	if noColorSet && noColorRaw != "" {
		p.record("HELM_COLOR", candidate{
			typ:      SourceEnv,
			location: "NO_COLOR",
			raw:      noColorRaw,
			value:    "never",
			external: true,
		})
	}
	if helmSet && helmRaw != "" {
		c := candidate{typ: SourceEnv, location: "HELM_COLOR", raw: helmRaw, external: true}
		switch v := strings.ToLower(helmRaw); v {
		case "never", "auto", "always":
			c.value = v
			helmEffective = v
		default:
			c.invalid = "not a recognized color mode"
			helmInvalid = c.invalid
		}
		p.record("HELM_COLOR", c)
	}

	if noColorSet && noColorRaw != "" {
		return "never"
	}
	if helmSet && helmRaw != "" {
		if helmInvalid != "" {
			return "auto"
		}
		return helmEffective
	}
	return "auto"
}

// setPathDefault registers that the built-in default of key is derived from a
// cache/config/data path helper.
func (p *provenance) setPathDefault(key string, origin helmpath.PathOrigin) {
	p.origins[key] = origin
}

func formatFloat(v float32) string {
	return strconv.FormatFloat(float64(v), 'f', 2, 32)
}

// canonicalValue renders the current effective field value for a key.
func (s *EnvSettings) canonicalValue(key string) string {
	switch key {
	case "HELM_NAMESPACE":
		return s.Namespace()
	case "HELM_DEBUG":
		return strconv.FormatBool(s.Debug)
	case "HELM_MAX_HISTORY":
		return strconv.Itoa(s.MaxHistory)
	case "KUBECONFIG":
		return s.KubeConfig
	case "HELM_KUBECONTEXT":
		return s.KubeContext
	case "HELM_KUBETOKEN":
		return s.KubeToken
	case "HELM_KUBEASUSER":
		return s.KubeAsUser
	case "HELM_KUBEASGROUPS":
		return strings.Join(s.KubeAsGroups, ",")
	case "HELM_KUBEAPISERVER":
		return s.KubeAPIServer
	case "HELM_KUBECAFILE":
		return s.KubeCaFile
	case "HELM_KUBEINSECURE_SKIP_TLS_VERIFY":
		return strconv.FormatBool(s.KubeInsecureSkipTLSVerify)
	case "HELM_KUBETLS_SERVER_NAME":
		return s.KubeTLSServerName
	case "HELM_PLUGINS":
		return s.PluginsDirectory
	case "HELM_REGISTRY_CONFIG":
		return s.RegistryConfig
	case "HELM_REPOSITORY_CONFIG":
		return s.RepositoryConfig
	case "HELM_REPOSITORY_CACHE":
		return s.RepositoryCache
	case "HELM_CONTENT_CACHE":
		return s.ContentCache
	case "HELM_BURST_LIMIT":
		return strconv.Itoa(s.BurstLimit)
	case "HELM_QPS":
		return formatFloat(s.QPS)
	case "HELM_COLOR":
		return s.ColorMode
	case "HELM_CACHE_HOME":
		v, _ := helmpath.CachePathOrigin()
		return v
	case "HELM_CONFIG_HOME":
		v, _ := helmpath.ConfigPathOrigin()
		return v
	case "HELM_DATA_HOME":
		v, _ := helmpath.DataPathOrigin()
		return v
	}
	return ""
}

// builtinDefault renders the built-in default value for a key.
func (p *provenance) builtinDefault(key string) candidate {
	c := candidate{typ: SourceDefault, location: "default"}
	switch key {
	case "HELM_NAMESPACE":
		c.value = "default"
	case "HELM_DEBUG", "HELM_KUBEINSECURE_SKIP_TLS_VERIFY":
		c.value = "false"
	case "HELM_MAX_HISTORY":
		c.value = strconv.Itoa(defaultMaxHistory)
	case "HELM_BURST_LIMIT":
		c.value = strconv.Itoa(defaultBurstLimit)
	case "HELM_QPS":
		c.value = formatFloat(defaultQPS)
	case "HELM_COLOR":
		c.value = "auto"
	case "HELM_CACHE_HOME", "HELM_CONFIG_HOME", "HELM_DATA_HOME",
		"HELM_PLUGINS", "HELM_REGISTRY_CONFIG", "HELM_REPOSITORY_CONFIG",
		"HELM_REPOSITORY_CACHE", "HELM_CONTENT_CACHE":
		if o, ok := p.origins[key]; ok {
			c.value = o.DefaultPath
		} else {
			var path string
			switch key {
			case "HELM_CACHE_HOME":
				path, _ = helmpath.CachePathOrigin()
			case "HELM_CONFIG_HOME":
				path, _ = helmpath.ConfigPathOrigin()
			case "HELM_DATA_HOME":
				path, _ = helmpath.DataPathOrigin()
			}
			c.value = path
		}
	default:
		c.value = ""
	}
	return c
}

// flagCandidate builds a candidate from a changed flag.
func (s *EnvSettings) flagCandidate(def *keyDef, flag *pflag.Flag) candidate {
	c := candidate{
		typ:      SourceFlag,
		location: "--" + flag.Name,
		raw:      flag.Value.String(),
		value:    s.canonicalValue(def.name),
	}
	if def.name == "HELM_KUBEASGROUPS" && len(s.KubeAsGroups) > 0 {
		c.raw = "[" + strings.Join(s.KubeAsGroups, ",") + "]"
	}
	return c
}

// namespaceKubeconfigCandidate observes the namespace carried by the current
// kubeconfig context without contacting the network.
func (s *EnvSettings) namespaceKubeconfigCandidate() candidate {
	c := candidate{typ: SourceKubeconfig}
	if s.config == nil {
		c.readError = "kubernetes configuration is not initialized"
		c.location = "kubeconfig context"
		return c
	}
	raw, err := s.config.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		c.readError = err.Error()
		c.location = "kubeconfig context"
		return c
	}
	ctxName := s.KubeContext
	if ctxName == "" {
		ctxName = raw.CurrentContext
	}
	c.location = fmt.Sprintf("kubeconfig context %q", ctxName)
	if ctx, ok := raw.Contexts[ctxName]; ok && ctx.Namespace != "" {
		c.raw = ctx.Namespace
		c.value = ctx.Namespace
	}
	return c
}

// pathCandidates returns the path variable and built-in default candidates for
// keys whose defaults derive from a path helper.
func (p *provenance) pathCandidates(key string) []candidate {
	o, ok := p.origins[key]
	if !ok {
		return nil
	}
	var out []candidate
	if o.Source != helmpath.BaseSourceDefault {
		out = append(out, candidate{
			typ:      SourcePath,
			location: o.EnvVar,
			raw:      o.Base,
			value:    o.Path,
			external: true,
		})
	}
	def := p.builtinDefault(key)
	out = append(out, def)
	return out
}

// baseCandidates resolves the HELM_*_HOME keys themselves from the live
// environment, matching the lazy path resolution order.
func baseCandidates(key string) []candidate {
	var path string
	var o helmpath.PathOrigin
	switch key {
	case "HELM_CACHE_HOME":
		path, o = helmpath.CachePathOrigin()
	case "HELM_CONFIG_HOME":
		path, o = helmpath.ConfigPathOrigin()
	case "HELM_DATA_HOME":
		path, o = helmpath.DataPathOrigin()
	default:
		return nil
	}
	var out []candidate
	if o.Source != helmpath.BaseSourceDefault {
		out = append(out, candidate{
			typ:      SourcePath,
			location: o.EnvVar,
			raw:      o.Base,
			value:    path,
			external: true,
		})
	}
	out = append(out, candidate{typ: SourceDefault, location: "default", value: o.DefaultPath})
	return out
}

// Provenance resolves the source of every effective CLI setting key. It must
// be called after the command flags have been parsed. The effective values in
// the report are the same values that the command actually uses.
func (s *EnvSettings) Provenance() *Report {
	p := s.prov
	if p == nil {
		p = newProvenance()
	}

	report := &Report{}
	keys := make([]*keyDef, len(p.order))
	copy(keys, p.order)
	sort.Slice(keys, func(i, j int) bool { return keys[i].name < keys[j].name })

	for _, def := range keys {
		key := def.name
		cs := append([]candidate(nil), p.found[key]...)

		// Command-line flags take precedence over every earlier source.
		if s.flags != nil {
			for _, name := range def.flags {
				if fl := s.flags.Lookup(name); fl != nil && fl.Changed {
					cs = append([]candidate{s.flagCandidate(def, fl)}, cs...)
				}
			}
		}

		// Namespace additionally falls back to the current kubeconfig context.
		if key == "HELM_NAMESPACE" {
			c := s.namespaceKubeconfigCandidate()
			switch {
			case c.readError != "":
				// A failed read is always recorded so it can be diagnosed,
				// even when a flag or environment variable covers it.
				cs = append(cs, c)
			case c.value != "":
				// A context carrying a namespace is recorded. When a flag or
				// environment variable already won it shows up shadowed.
				cs = append(cs, c)
			default:
				// The context exists but carries no namespace: there is no
				// kubeconfig-provided value for this key.
			}
		}

		// Defaults derived from path helpers.
		if _, ok := p.origins[key]; ok {
			cs = append(cs, p.pathCandidates(key)...)
		} else if key == "HELM_CACHE_HOME" || key == "HELM_CONFIG_HOME" || key == "HELM_DATA_HOME" {
			cs = append(cs, baseCandidates(key)...)
		} else {
			cs = append(cs, p.builtinDefault(key))
		}

		info := SettingInfo{Key: key, Value: s.canonicalValue(key), Sensitive: def.sensitive}
		winningIdx := -1
		for i, c := range cs {
			if c.invalid == "" && c.readError == "" {
				winningIdx = i
				break
			}
		}
		// Fallback for safety: the built-in default always resolves.
		if winningIdx == -1 {
			for i, c := range cs {
				if c.typ == SourceDefault {
					winningIdx = i
					break
				}
			}
		}

		var winner *candidate
		if winningIdx >= 0 {
			w := cs[winningIdx]
			winner = &w
		}

		distinct := map[string]*ConflictValue{}
		var distinctOrder []string

		for i := range cs {
			c := cs[i]
			vs := ValueSource{
				Type:      c.typ,
				Location:  c.location,
				RawValue:  c.raw,
				Value:     c.value,
				External:  c.external,
				Invalid:   c.invalid,
				ReadError: c.readError,
			}
			switch {
			case c.invalid == "" && c.readError == "":
				if i == winningIdx {
					vs.Winning = true
				} else if winner != nil {
					switch {
					case c.typ == SourceKubeconfig && winner.typ == SourceKubeconfig:
						vs.ShadowReason = "lower precedence"
					case c.value == winner.value:
						vs.ShadowReason = fmt.Sprintf("same value also provided by the effective %s %s", winner.typ, winner.location)
					default:
						vs.ShadowReason = fmt.Sprintf("overridden by the effective %s %s", winner.typ, winner.location)
					}
				}
				if c.typ != SourceDefault {
					if _, ok := distinct[c.value]; !ok {
						cv := &ConflictValue{Value: c.value}
						distinct[c.value] = cv
						distinctOrder = append(distinctOrder, c.value)
					}
					distinct[c.value].Locations = append(distinct[c.value].Locations, vs)
				}
			case c.readError != "":
				if winner != nil {
					vs.ShadowReason = fmt.Sprintf("source could not be read (%s); the effective %s %s was used instead", c.readError, winner.typ, winner.location)
				}
				report.ReadErrors = append(report.ReadErrors, SourceReadError{
					Key: key, Source: c.typ, Location: c.location, Err: c.readError,
				})
			default:
				reason := fmt.Sprintf("invalid value, fell back to the next source (%s)", c.invalid)
				if winner != nil {
					reason = fmt.Sprintf("invalid value, the effective %s %s was used instead (%s)", winner.typ, winner.location, c.invalid)
				}
				vs.ShadowReason = reason
			}
			info.Sources = append(info.Sources, vs)
		}

		if winner != nil {
			info.External = winner.external
		}

		// A key counts as without any explicit source when every candidate
		// other than the built-in default is absent. An invalid or unreadable
		// source still counts as a source attempt, so such keys are excluded.
		nonDefaultCandidates := 0
		for _, c := range cs {
			if c.typ != SourceDefault {
				nonDefaultCandidates++
			}
		}
		if nonDefaultCandidates == 0 && winner != nil && winner.typ == SourceDefault {
			report.Unset = append(report.Unset, key)
		}

		if len(distinctOrder) > 1 {
			conflict := Conflict{Key: key}
			for _, v := range distinctOrder {
				cv := distinct[v]
				if winner != nil && cv.Value == winner.value {
					cv.Effective = true
				}
				conflict.Values = append(conflict.Values, *cv)
			}
			report.Conflicts = append(report.Conflicts, conflict)
		}

		// Invalid format candidates are reported even when a higher
		// precedence source covers them, since they indicate external
		// configuration noise.
		for _, c := range cs {
			if c.invalid != "" {
				report.Invalid = append(report.Invalid, Diagnostic{
					Key:      key,
					Source:   c.typ,
					Location: c.location,
					RawValue: c.raw,
					Expected: def.expected,
					Reason:   c.invalid,
				})
			}
		}

		// Semantic validation of the effective value.
		if def.nonnegative {
			if invalid := negativeSemantic(key, info.Value); invalid != nil {
				d := Diagnostic{
					Key:      key,
					Expected: def.expected,
					Reason:   invalid.Error(),
				}
				if winner != nil {
					d.Source = winner.typ
					d.Location = winner.location
					d.RawValue = winner.raw
				}
				report.Invalid = append(report.Invalid, d)
			}
		}

		// Redact credential settings after all comparisons are done.
		if def.sensitive {
			redact(&info)
			for ci := range report.Conflicts {
				if report.Conflicts[ci].Key != key {
					continue
				}
				for vi := range report.Conflicts[ci].Values {
					if report.Conflicts[ci].Values[vi].Value != "" {
						report.Conflicts[ci].Values[vi].Value = redactedValue
					}
					for li := range report.Conflicts[ci].Values[vi].Locations {
						redactSource(&report.Conflicts[ci].Values[vi].Locations[li])
					}
				}
			}
			for di := range report.Invalid {
				if report.Invalid[di].Key == key && report.Invalid[di].RawValue != "" {
					report.Invalid[di].RawValue = redactedValue
				}
			}
		}

		report.Settings = append(report.Settings, info)
	}

	// Re-order read errors/invalid diagnostics by key for stable output.
	sort.SliceStable(report.ReadErrors, func(i, j int) bool {
		if report.ReadErrors[i].Key == report.ReadErrors[j].Key {
			return report.ReadErrors[i].Location < report.ReadErrors[j].Location
		}
		return report.ReadErrors[i].Key < report.ReadErrors[j].Key
	})

	return report
}

func negativeSemantic(key, value string) error {
	switch key {
	case "HELM_MAX_HISTORY":
		if v, err := strconv.Atoi(value); err == nil && v < 0 {
			return fmt.Errorf("must be 0 or greater (0 means unlimited), got %d", v)
		}
	case "HELM_QPS":
		if v, err := strconv.ParseFloat(value, 32); err == nil && v < 0 {
			return fmt.Errorf("must be 0 or greater, got %s", value)
		}
	}
	return nil
}

// redact replaces the raw and displayed values of credential settings.
func redact(info *SettingInfo) {
	if info.Value != "" {
		info.Value = redactedValue
	}
	for i := range info.Sources {
		redactSource(&info.Sources[i])
	}
}

// redactSource replaces the non-empty values of one credential source.
func redactSource(src *ValueSource) {
	if src.RawValue != "" {
		src.RawValue = redactedValue
	}
	if src.Value != "" {
		src.Value = redactedValue
	}
}

// Validate returns diagnostics for every setting whose effective value or any
// of its sources is invalid. It performs no network access.
func (s *EnvSettings) Validate() []Diagnostic {
	return s.Provenance().Invalid
}

// Keys returns the sorted list of setting keys covered by the report.
func (s *EnvSettings) Keys() []string {
	p := s.prov
	if p == nil {
		p = newProvenance()
	}
	keys := make([]string, 0, len(p.order))
	for _, d := range p.order {
		keys = append(keys, d.name)
	}
	sort.Strings(keys)
	return keys
}

// quote renders a value for the human report.
func quote(v string) string {
	if v == "" {
		return `""`
	}
	return strconv.Quote(v)
}

// sourceLabel renders a source type and location pair.
func sourceLabel(s ValueSource) string {
	label := string(s.Type)
	switch s.Type {
	case SourceFlag:
		label = "flag " + s.Location
	case SourceEnv, SourcePath:
		label = fmt.Sprintf("%s %s", s.Type, s.Location)
	case SourceKubeconfig:
		label = s.Location
	case SourceDefault:
		label = "default"
	}
	if s.External {
		label += " [external]"
	}
	return label
}

// WriteReport writes the human readable form of the report to w. When key is
// empty every setting is listed; otherwise only the given key is shown.
func WriteReport(w io.Writer, report *Report, key string) error {
	if key != "" {
		for _, info := range report.Settings {
			if info.Key == key {
				return writeKeyBlock(w, info)
			}
		}
		return fmt.Errorf("unknown setting key %q; run \"helm settings\" to list the available keys", key)
	}

	if _, err := fmt.Fprintln(w, "EFFECTIVE CLI SETTINGS"); err != nil {
		return err
	}
	for _, info := range report.Settings {
		winner := ""
		for _, src := range info.Sources {
			if src.Winning {
				winner = sourceLabel(src)
				break
			}
		}
		if _, err := fmt.Fprintf(w, "%s=%s  (%s)\n", info.Key, info.Value, winner); err != nil {
			return err
		}
	}

	// Expand keys with more than one source, invalid values or read errors so
	// that every observed value (including shadowed ones) is visible.
	var expanded []SettingInfo
	for _, info := range report.Settings {
		interesting := len(info.Sources) > 1
		for _, src := range info.Sources {
			if src.Invalid != "" || src.ReadError != "" {
				interesting = true
			}
		}
		if interesting {
			expanded = append(expanded, info)
		}
	}
	if len(expanded) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "MULTIPLE OR SHADOWED SOURCES")
		for _, info := range expanded {
			if err := writeKeyBlock(w, info); err != nil {
				return err
			}
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "SUMMARY")
	if len(report.Unset) == 0 {
		fmt.Fprintln(w, "Keys without any explicit source: none")
	} else {
		fmt.Fprintf(w, "Keys without any explicit source (using built-in default): %s\n", strings.Join(report.Unset, ", "))
	}
	if len(report.Conflicts) == 0 {
		fmt.Fprintln(w, "Keys with conflicting multi-source values: none")
	} else {
		fmt.Fprintln(w, "Keys with conflicting multi-source values:")
		for _, c := range report.Conflicts {
			parts := make([]string, 0, len(c.Values))
			for _, v := range c.Values {
				mark := ""
				if v.Effective {
					mark = " [effective]"
				}
				locs := make([]string, len(v.Locations))
				for i, l := range v.Locations {
					locs[i] = sourceLabel(l)
				}
				parts = append(parts, fmt.Sprintf("%s from %s%s", quote(v.Value), strings.Join(locs, ", "), mark))
			}
			fmt.Fprintf(w, "  %s: %s\n", c.Key, strings.Join(parts, "; "))
		}
	}
	if len(report.Invalid) > 0 {
		fmt.Fprintln(w, "Invalid values:")
		for _, d := range report.Invalid {
			fmt.Fprintf(w, "  %s\n", d.String())
		}
	}
	if len(report.ReadErrors) > 0 {
		fmt.Fprintln(w, "Sources that could not be read:")
		for _, e := range report.ReadErrors {
			fmt.Fprintf(w, "  %s: %s %s: %s\n", e.Key, e.Source, e.Location, e.Err)
		}
	}
	return nil
}

// writeKeyBlock writes the full source detail of one setting key.
func writeKeyBlock(w io.Writer, info SettingInfo) error {
	if _, err := fmt.Fprintf(w, "\n%s\n", info.Key); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  effective value: %s\n", quote(info.Value)); err != nil {
		return err
	}
	if len(info.Sources) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "  sources, in precedence order:"); err != nil {
		return err
	}
	for _, src := range info.Sources {
		// For invalid candidates show the raw token, since no normalized
		// value exists for it.
		displayed := src.Value
		if src.Invalid != "" {
			displayed = src.RawValue
		}
		line := fmt.Sprintf("    %s: %s", sourceLabel(src), quote(displayed))
		switch {
		case src.Winning:
			line += "  [effective]"
		case src.Invalid != "":
			line += "  invalid: " + src.Invalid
		case src.ReadError != "":
			line += "  unreadable: " + src.ReadError
		case src.ShadowReason != "":
			line += "  shadowed: " + src.ShadowReason
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}
