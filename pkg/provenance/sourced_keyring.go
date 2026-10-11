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
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// KeyFileError reports why one file inside a key directory could not be read.
type KeyFileError struct {
	Path   string
	Reason string
}

// SourceLoadResult reports what happened when one key source was loaded.
type SourceLoadResult struct {
	// Name is the effective source name used in judgments and source counts.
	Name string
	// Path is the file or directory location.
	Path string
	// Origins lists where the source was declared (policy files or command
	// line).
	Origins []string
	// IsDir is true when Path was a directory.
	IsDir bool
	// Counted is true when at least one key was loaded from the source.
	Counted bool
	// KeyCount is the number of keys loaded from the source (including keys
	// already contributed by another source).
	KeyCount int
	// Reason explains why the source as a whole was not counted.
	Reason string
	// FileErrors explains individual unreadable files within a directory.
	FileErrors []KeyFileError
}

// PolicySignatory is a Signatory whose keyring was merged from several named
// sources. Each public key is annotated with the sources it was found in, and
// a key appearing in more than one source is stored once.
type PolicySignatory struct {
	Signatory

	// keySources maps an upper-case primary key fingerprint to the ordered,
	// de-duplicated list of source names the key was found in.
	keySources map[string][]string

	loadResults []SourceLoadResult
	policy      *EffectivePolicy
}

// NewPolicySignatory loads every source declared in the effective policy and
// merges the keys into one keyring. A source that cannot be parsed does not
// abort loading: the other sources still participate, and the per-source
// outcome is kept for the verification report.
func NewPolicySignatory(eff *EffectivePolicy) *PolicySignatory {
	ps := &PolicySignatory{
		keySources: map[string][]string{},
		policy:     eff,
	}

	// Keep entity insertion stable by fingerprint while merging; order is
	// restored to source declaration order afterwards.
	byFP := map[string]*mergedEntity{}
	order := 0

	for i := range eff.sources {
		src := &eff.sources[i]
		result := SourceLoadResult{Name: src.name, Path: src.path, Origins: append([]string(nil), src.origins...)}

		fi, err := os.Stat(src.path)
		switch {
		case err != nil:
			result.Reason = err.Error()
		case fi.IsDir():
			src.dir = true
			result.IsDir = true
			keys, fileErrors := loadKeyDirectory(src.path)
			result.FileErrors = fileErrors
			result.KeyCount = addEntities(keys, src.name, ps.keySources, byFP, &order)
		default:
			ring, err := loadKeyRing(src.path)
			switch {
			case err != nil:
				result.Reason = err.Error()
			case len(ring) == 0:
				result.Reason = "keyring contains no keys"
			default:
				result.KeyCount = addEntities(ring, src.name, ps.keySources, byFP, &order)
			}
		}

		result.Counted = result.KeyCount > 0
		ps.loadResults = append(ps.loadResults, result)
	}

	entities := make([]*mergedEntity, 0, len(byFP))
	for _, m := range byFP {
		entities = append(entities, m)
	}
	sort.Slice(entities, func(i, j int) bool { return entities[i].order < entities[j].order })

	ps.KeyRing = make(openpgp.EntityList, 0, len(entities))
	for _, m := range entities {
		ps.KeyRing = append(ps.KeyRing, m.entity)
	}
	return ps
}

// mergedEntity is one unique public key and its first-seen order.
type mergedEntity struct {
	entity *openpgp.Entity
	order  int
}

// addEntities merges entities loaded from one source into the fingerprint
// indexes and returns how many entities were processed.
func addEntities(
	ring openpgp.EntityList,
	sourceName string,
	keySources map[string][]string,
	byFP map[string]*mergedEntity,
	order *int,
) int {
	count := 0
	for _, e := range ring {
		if e == nil || e.PrimaryKey == nil {
			continue
		}
		count++
		fp := fingerprintOf(e)
		if _, ok := byFP[fp]; !ok {
			byFP[fp] = &mergedEntity{entity: e, order: *order}
			*order++
		}
		if !slices.Contains(keySources[fp], sourceName) {
			keySources[fp] = append(keySources[fp], sourceName)
		}
	}
	return count
}

// loadKeyDirectory reads every regular file in a directory as a keyring.
// Unreadable files are reported but do not abort the directory load.
func loadKeyDirectory(dir string) (openpgp.EntityList, []KeyFileError) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []KeyFileError{{Path: dir, Reason: err.Error()}}
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	var ring openpgp.EntityList
	var fileErrors []KeyFileError
	for _, name := range names {
		p := filepath.Join(dir, name)
		keys, err := loadKeyRing(p)
		switch {
		case err != nil:
			fileErrors = append(fileErrors, KeyFileError{Path: p, Reason: err.Error()})
			continue
		case len(keys) == 0:
			fileErrors = append(fileErrors, KeyFileError{Path: p, Reason: "keyring contains no keys"})
			continue
		}
		ring = append(ring, keys...)
	}
	return ring, fileErrors
}

// fingerprintOf returns the upper-case hex primary key fingerprint of an
// entity.
func fingerprintOf(e *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
}

// countedSourceNames returns the names of sources that contributed at least
// one key, in declaration order.
func (ps *PolicySignatory) countedSourceNames() []string {
	var out []string
	for _, r := range ps.loadResults {
		if r.Counted && !slices.Contains(out, r.Name) {
			out = append(out, r.Name)
		}
	}
	return out
}

// describeSourceAccounting renders the counted/not-counted source summary
// required when a source fails to parse.
func (ps *PolicySignatory) describeSourceAccounting() string {
	counted := ps.countedSourceNames()
	var b strings.Builder
	fmt.Fprintf(&b, "  Key Sources Counted: %d", len(counted))
	if len(counted) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(counted, ", "))
	}
	b.WriteString("; ")

	var failed []SourceLoadResult
	for _, r := range ps.loadResults {
		if !r.Counted {
			failed = append(failed, r)
		}
	}
	fmt.Fprintf(&b, "Not Counted: %d", len(failed))
	for i, r := range failed {
		detail := r.Reason
		if detail == "" && len(r.FileErrors) > 0 {
			detail = fmt.Sprintf("%d of %d files unreadable", len(r.FileErrors), len(r.FileErrors))
		}
		fmt.Fprintf(&b, "%s %s: %s", separator(i), r.Path, detail)
	}
	b.WriteString("\n")

	// Report individual unreadable files inside directories that otherwise
	// counted.
	for _, r := range ps.loadResults {
		if r.Counted {
			for _, fe := range r.FileErrors {
				fmt.Fprintf(&b, "  Key Source File Not Counted: %s: %s\n", fe.Path, fe.Reason)
			}
		}
	}
	return b.String()
}

func separator(i int) string {
	if i == 0 {
		return ""
	}
	return ";"
}
