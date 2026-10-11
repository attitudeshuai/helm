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

package util

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	chart "helm.sh/helm/v4/pkg/chart"
)

// SourceCategory identifies where a merged value originated.
type SourceCategory string

// Source categories recorded by the value provenance tracker.
const (
	// SourceChartDefault is a leaf coming from a chart's values.yaml defaults.
	SourceChartDefault SourceCategory = "chart-default"
	// SourceParentOverride is a leaf a parent chart supplied for a dependency.
	SourceParentOverride SourceCategory = "parent-override"
	// SourceValuesFile is a leaf supplied via -f/--values.
	SourceValuesFile SourceCategory = "values-file"
	// SourceSet is a leaf supplied via --set.
	SourceSet SourceCategory = "set"
	// SourceSetString is a leaf supplied via --set-string.
	SourceSetString SourceCategory = "set-string"
	// SourceSetFile is a leaf supplied via --set-file.
	SourceSetFile SourceCategory = "set-file"
	// SourceSetJSON is a leaf supplied via --set-json.
	SourceSetJSON SourceCategory = "set-json"
	// SourceSetLiteral is a leaf supplied via --set-literal.
	SourceSetLiteral SourceCategory = "set-literal"
	// SourceHistory is a leaf reused from a previous release. Such values do
	// not carry source location information.
	SourceHistory SourceCategory = "reused-values"
	// SourceGlobal is a leaf propagated into a chart through .Values.global.
	SourceGlobal SourceCategory = "global"
	// SourceImport is a leaf brought in through the import-values mechanism.
	SourceImport SourceCategory = "import-values"
)

// ValueSource describes one assignment of a value from a specific source.
type ValueSource struct {
	// Category is the kind of source that provided the value.
	Category SourceCategory
	// Location points at the concrete file or argument that supplied it. It
	// may be empty for sources without location information (reused values).
	Location string
}

func (s ValueSource) String() string {
	if s.Location == "" {
		return string(s.Category)
	}
	return fmt.Sprintf("%s (%s)", s.Category, s.Location)
}

// provenanceOp records how a value took effect at a particular merge step.
type provenanceOp int

const (
	// opMerge means the value took effect through deep merging of tables.
	opMerge provenanceOp = iota
	// opReplace means a scalar or an array replaced a previous value.
	opReplace
	// opDelete means a null value removed a previously non-null key.
	opDelete
)

// provEvent is a single entry in a leaf's override chain.
type provEvent struct {
	src ValueSource
	op  provenanceOp
	typ string
}

// ProvNode is an opaque node in the provenance shadow tree. It mirrors a map
// node in the values being merged and records the ordered source chain for
// each of its leaves.
type ProvNode struct {
	events   []provEvent
	children map[string]*ProvNode
}

func newProvNode() *ProvNode {
	return &ProvNode{}
}

// Clone returns a deep copy of the shadow node.
func (n *ProvNode) Clone() *ProvNode { return n.clone() }

func (n *ProvNode) ensureChildren() map[string]*ProvNode {
	if n.children == nil {
		n.children = map[string]*ProvNode{}
	}
	return n.children
}

func (n *ProvNode) isLeaf() bool {
	return len(n.children) == 0
}

// clone deep-copies a shadow node.
func (n *ProvNode) clone() *ProvNode {
	if n == nil {
		return nil
	}
	c := &ProvNode{}
	if len(n.events) > 0 {
		c.events = append(c.events, n.events...)
	}
	if len(n.children) > 0 {
		c.children = make(map[string]*ProvNode, len(n.children))
		for k, child := range n.children {
			c.children[k] = child.clone()
		}
	}
	return c
}

// appendEvents adds events to a node, collapsing adjacent identical events.
func appendEvents(n *ProvNode, evs ...provEvent) {
	for _, ev := range evs {
		if len(n.events) > 0 {
			last := n.events[len(n.events)-1]
			if last.src == ev.src && last.op == ev.op && last.typ == ev.typ {
				continue
			}
		}
		n.events = append(n.events, ev)
	}
}

// lastEvent returns the most recent event recorded on the node.
func (n *ProvNode) lastEvent() provEvent {
	if n == nil || len(n.events) == 0 {
		return provEvent{}
	}
	return n.events[len(n.events)-1]
}

// joinNodes merges the lower-precedence node with the higher-precedence node.
// Events are ordered lower-precedence first so that the chain keeps the value
// that got overridden. When both sides hold leaves, the higher node replaces
// the lower one; tables are deep-merged. The returned node is always a fresh
// node; the inputs are not modified.
func joinNodes(lower, higher *ProvNode) *ProvNode {
	switch {
	case lower == nil:
		return higher.clone()
	case higher == nil:
		return lower.clone()
	}
	out := newProvNode()
	appendEvents(out, lower.events...)
	appendEvents(out, higher.events...)
	if lower.isLeaf() && higher.isLeaf() {
		// A leaf winning over another leaf is a wholesale replacement.
		if len(out.events) > 0 {
			out.events[len(out.events)-1].op = opReplace
		}
		return out
	}
	if lower.isLeaf() != higher.isLeaf() {
		// Shape mismatches are reported as conflicts by the caller; here the
		// higher-precedence node simply wins for the shadow tree.
		if len(out.events) > 0 {
			out.events[len(out.events)-1].op = opReplace
		}
		return out
	}
	children := out.ensureChildren()
	for k, lv := range lower.children {
		children[k] = lv.clone()
	}
	for k, hv := range higher.children {
		if lv, ok := children[k]; ok {
			children[k] = joinNodes(lv, hv)
		} else {
			children[k] = hv.clone()
		}
	}
	return out
}

// retagTrailing changes the category of the most recent event of every leaf
// below n, without touching event ordering. Used when chart defaults cross a
// chart boundary (parent chart overrides, globals, imports).
func retagTrailing(n *ProvNode, cat SourceCategory, location string) {
	if n == nil {
		return
	}
	if n.isLeaf() {
		if len(n.events) > 0 {
			n.events[len(n.events)-1].src.Category = cat
			if location != "" {
				n.events[len(n.events)-1].src.Location = location
			}
		}
		return
	}
	for _, child := range n.children {
		retagTrailing(child, cat, location)
	}
}

// tagLeaves appends an event to every leaf below n.
func tagLeaves(n *ProvNode, ev provEvent) {
	if n == nil {
		return
	}
	if n.isLeaf() {
		appendEvents(n, ev)
		return
	}
	for _, child := range n.children {
		tagLeaves(child, ev)
	}
}

// markHistory retags every event below n as reused historical values without
// location information.
func markHistory(n *ProvNode) {
	if n == nil {
		return
	}
	for i := range n.events {
		n.events[i].src = ValueSource{Category: SourceHistory}
	}
	for _, child := range n.children {
		markHistory(child)
	}
}

// subNode walks the shadow tree following the dotted key path. Missing nodes
// return nil.
func subNode(n *ProvNode, keys ...string) *ProvNode {
	cur := n
	for _, k := range keys {
		if cur == nil || cur.children == nil {
			return nil
		}
		cur = cur.children[k]
	}
	return cur
}

// rebase creates a new shadow tree rooted at the given dotted path, mirroring
// pathToMap used by the import-values processing.
func rebase(root *ProvNode, parentPath []string) *ProvNode {
	if len(parentPath) == 0 || (len(parentPath) == 1 && parentPath[0] == ".") {
		return root.clone()
	}
	// Build from the deepest level upwards.
	var cur *ProvNode
	if root != nil {
		cur = root.clone()
	}
	for i := len(parentPath) - 1; i >= 0; i-- {
		k := parentPath[i]
		if k == "" || k == "." {
			continue
		}
		parent := newProvNode()
		parent.ensureChildren()[k] = cur
		cur = parent
	}
	if cur == nil {
		cur = newProvNode()
	}
	return cur
}

// TypeConflict describes one assignment that could not take effect (or took
// effect by replacement) because the incoming value had a different type than
// the existing value.
type TypeConflict struct {
	// Path is the dotted key path.
	Path string
	// Message describes the conflict.
	Message string
	// Kept is the source of the value that remained in effect.
	Kept ValueSource
	// KeptType is the type of the kept value.
	KeptType string
	// Dropped is the source of the value that was replaced or skipped.
	Dropped ValueSource
	// DroppedType is the type of the dropped value.
	DroppedType string
}

// ValueRecord is the provenance record for one effective (or removed) leaf.
type ValueRecord struct {
	// Path is the dotted key path.
	Path string
	// Value is the final effective value; it is nil for removed leaves.
	Value any
	// Sources holds the full override chain, oldest first. The final entry is
	// the effective source.
	Sources []ValueSource
	// Final is the effective source (last entry of Sources).
	Final ValueSource
	// Replaced distinguishes wholesale replaced scalars/arrays from leaves
	// taking effect through deep table merges.
	Replaced bool
	// Deleted marks leaves removed by a null value.
	Deleted bool
}

// Report is the deterministic provenance report.
type Report struct {
	// Merged lists effective leaves that took effect through deep table merges.
	Merged []ValueRecord
	// Replaced lists effective leaves whose scalar/array value was replaced.
	Replaced []ValueRecord
	// Removed lists leaves deleted by null values.
	Removed []ValueRecord
	// Conflicts lists type mismatch diagnostics.
	Conflicts []TypeConflict
	// Notes lists non-fatal diagnostics such as unresolvable locations.
	Notes []string
}

// Tracker records value sources during one chart value merge operation. The
// zero value is not usable; create one with NewTracker.
type Tracker struct {
	root *ProvNode
	// lastValues mirrors the result of the most recent tracked coalesce and
	// is used for value previews in reports.
	lastValues map[string]any

	// Shared state with auxiliary trackers.
	shared *provShared
	// aux trackers only publish chart shadow registrations; their records,
	// removals and conflicts are discarded.
	aux bool
}

type provShared struct {
	// registry stores the shadow mirroring current c.Values for charts whose
	// defaults were rewritten (import-values, reused values).
	registry map[any]*ProvNode
	removed  map[string]*ProvNode
	conflicts []TypeConflict
	locations []string
}

// NewTracker creates an empty provenance tracker.
func NewTracker() *Tracker {
	return &Tracker{root: newProvNode(), shared: &provShared{
		registry: map[any]*ProvNode{},
		removed:  map[string]*ProvNode{},
	}}
}

// Aux returns an auxiliary tracker sharing the chart shadow registry. Auxiliary
// coalescing runs (e.g. rebuilding old release values) do not contribute
// records, removals or conflicts to the parent report.
func (t *Tracker) Aux() *Tracker {
	return &Tracker{root: newProvNode(), shared: t.shared, aux: true}
}

// Root returns the root shadow node.
func (t *Tracker) Root() *ProvNode { return t.root }

// SetRoot replaces the root shadow node.
func (t *Tracker) SetRoot(n *ProvNode) {
	if n == nil {
		n = newProvNode()
	}
	t.root = n
}

// DeepCopyRoot replaces the root shadow with a deep copy of itself, matching
// the deep copy that CoalesceValues performs on the values map.
func (t *Tracker) DeepCopyRoot() {
	t.root = t.root.clone()
}

// EmptyShadow returns a shadow node with no events or children.
func (t *Tracker) EmptyShadow() *ProvNode { return newProvNode() }

// ShadowForMap builds a shadow tree mirroring m where every leaf is tagged
// with src.
func (t *Tracker) ShadowForMap(m map[string]any, src ValueSource) *ProvNode {
	return shadowForMap(m, src)
}

func shadowForMap(m map[string]any, src ValueSource) *ProvNode {
	n := newProvNode()
	buildShadow(n, m, src)
	return n
}

func buildShadow(n *ProvNode, m map[string]any, src ValueSource) {
	children := n.ensureChildren()
	for k, v := range m {
		child := newProvNode()
		if vm, ok := v.(map[string]any); ok {
			buildShadow(child, vm, src)
		} else {
			appendEvents(child, provEvent{src: src, op: opMerge, typ: valueTypeName(v)})
		}
		children[k] = child
	}
}

// RegisterChart records that the supplied chart's current Values() are
// mirrored by n. Subsequent tracked coalescing uses n instead of synthesizing
// chart-default provenance.
func (t *Tracker) RegisterChart(ch chart.Charter, n *ProvNode) {
	if t == nil || ch == nil || n == nil {
		return
	}
	t.shared.registry[ch] = n
}

// ChartShadow returns the registered shadow for a chart, if any.
func (t *Tracker) ChartShadow(ch chart.Charter) (*ProvNode, bool) {
	if t == nil || ch == nil {
		return nil, false
	}
	n, ok := t.shared.registry[ch]
	return n, ok
}

// MarkCheckableLocation records a user-supplied local file path whose
// existence is checked when rendering the report. URLs and stdin ("-") must
// not be passed here.
func (t *Tracker) MarkCheckableLocation(loc string) {
	if t == nil || loc == "" || loc == "-" || strings.Contains(loc, "://") {
		return
	}
	t.shared.locations = append(t.shared.locations, loc)
}

func (t *Tracker) recordRemoved(fullKey string, n *ProvNode) {
	if t == nil || t.aux || n == nil {
		return
	}
	if existing, ok := t.shared.removed[fullKey]; ok {
		n = joinNodes(existing, n)
	}
	t.shared.removed[fullKey] = n
}

func (t *Tracker) recordConflict(c TypeConflict) {
	if t == nil || t.aux {
		return
	}
	t.shared.conflicts = append(t.shared.conflicts, c)
}

// conflict builds and records a type conflict if both value types are known
// and differ.
func (t *Tracker) conflict(fullKey, message string, keptNode, droppedNode *ProvNode, keptVal, droppedVal any) {
	if t == nil || t.aux {
		return
	}
	kt, dt := valueTypeName(keptVal), valueTypeName(droppedVal)
	if kt == dt || kt == "unknown" || dt == "unknown" {
		return
	}
	t.recordConflict(TypeConflict{
		Path:        fullKey,
		Message:     message,
		Kept:        keptNode.lastEvent().src,
		KeptType:    kt,
		Dropped:     droppedNode.lastEvent().src,
		DroppedType: dt,
	})
}

// MergeMapsShadow mirrors loader.MergeMaps: b is merged into the shadow root a,
// tables are deep-merged and every other value is replaced wholesale.
func (t *Tracker) MergeMapsShadow(a, b *ProvNode) *ProvNode {
	return mergeMapsShadow(a, b)
}

func mergeMapsShadow(a, b *ProvNode) *ProvNode {
	if a == nil {
		return b.clone()
	}
	if b == nil {
		return a.clone()
	}
	out := a.clone()
	if len(b.children) > 0 {
		out.ensureChildren()
	}
	for k, bv := range b.children {
		av, ok := out.children[k]
		if !ok {
			out.children[k] = bv.clone()
			continue
		}
		if !av.isLeaf() && !bv.isLeaf() {
			out.children[k] = mergeMapsShadow(av, bv)
			continue
		}
		// MergeMaps replaces scalars/arrays regardless of the previous
		// shape; shape mismatches surface as type conflicts in the coalesce.
		out.children[k] = joinNodes(av, bv)
	}
	return out
}

// RecordSetContribution merges the leaves of a parsed --set* argument into the
// root shadow. Tables deep-merge, scalars and arrays replace wholesale.
func (t *Tracker) RecordSetContribution(contrib map[string]any, src ValueSource) {
	if t == nil || len(contrib) == 0 {
		return
	}
	t.root = mergeMapsShadow(t.root, shadowForMap(contrib, src))
}

// MergeShadowInto merges srcN into dstN with loader.MergeMaps semantics.
func (t *Tracker) MergeShadowInto(dstN, srcN *ProvNode) *ProvNode {
	return mergeMapsShadow(dstN, srcN)
}

// SubNode walks a shadow node following a dotted path.
func (t *Tracker) SubNode(n *ProvNode, dotted string) *ProvNode {
	if n == nil {
		return nil
	}
	if dotted == "" || dotted == "." {
		return n
	}
	return subNode(n, strings.Split(dotted, ".")...)
}

// RebaseShadow re-roots n at the given dotted parent path.
func (t *Tracker) RebaseShadow(n *ProvNode, parent string) *ProvNode {
	return rebase(n, strings.Split(parent, "."))
}

// TagSubtree appends a merge event to every leaf below n, used for values
// propagated by globals and import-values.
func (t *Tracker) TagSubtree(n *ProvNode, src ValueSource) {
	tagLeaves(n, provEvent{src: src, op: opMerge, typ: ""})
}

// RetagTrailing changes the trailing event category of every leaf below n.
func (t *Tracker) RetagTrailing(n *ProvNode, cat SourceCategory) {
	retagTrailing(n, cat, "")
}

// MarkHistory labels every event below n as reused historical values.
func (t *Tracker) MarkHistory(n *ProvNode) {
	markHistory(n)
}

// TrimNilLeaves removes leaf nodes tagged as null, mirroring the nil trimming
// performed by the import-values processing.
func (t *Tracker) TrimNilLeaves(n *ProvNode) {
	if n == nil {
		return
	}
	for k, child := range n.children {
		if child.isLeaf() && child.lastEvent().typ == "null" {
			delete(n.children, k)
			continue
		}
		t.TrimNilLeaves(child)
	}
}

// valueTypeName returns a stable, human readable type name.
func valueTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "table"
	case []any:
		return "list"
	case string:
		return "string"
	case bool:
		return "bool"
	case int, int32, int64:
		return "int"
	case float32, float64:
		return "float"
	default:
		return "unknown"
	}
}

// chartValuesLocation returns the conventional location of a chart's default
// values file.
func chartValuesLocation(ch chart.Charter) string {
	ac, err := chart.NewAccessor(ch)
	if err != nil {
		return "values.yaml"
	}
	return path.Join(ac.ChartFullPath(), "values.yaml")
}

// collectRecords walks the final shadow tree and renders value records.
func (t *Tracker) collectRecords() (merged, replaced []ValueRecord) {
	if t == nil || t.root == nil {
		return nil, nil
	}
	var walk func(prefix string, n *ProvNode, ownVal any)
	walk = func(prefix string, n *ProvNode, ownVal any) {
		if n == nil {
			return
		}
		if n.isLeaf() {
			if len(n.events) == 0 {
				return
			}
			sources := make([]ValueSource, 0, len(n.events))
			for _, ev := range n.events {
				if len(sources) > 0 && sources[len(sources)-1] == ev.src {
					continue
				}
				sources = append(sources, ev.src)
			}
			rec := ValueRecord{
				Path:    prefix,
				Sources: sources,
				Final:   sources[len(sources)-1],
				Value:   ownVal,
			}
			if n.lastEvent().op == opReplace {
				rec.Replaced = true
				replaced = append(replaced, rec)
			} else {
				merged = append(merged, rec)
			}
			return
		}
		ownMap, _ := ownVal.(map[string]any)
		keys := make([]string, 0, len(n.children))
		for k := range n.children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			var childVal any
			if ownMap != nil {
				childVal = ownMap[k]
			}
			walk(concatPrefix(prefix, k), n.children[k], childVal)
		}
	}
	walk("", t.root, t.lastValues)
	sort.Slice(merged, func(i, j int) bool { return merged[i].Path < merged[j].Path })
	sort.Slice(replaced, func(i, j int) bool { return replaced[i].Path < replaced[j].Path })
	return merged, replaced
}

// Report builds the deterministic provenance report.
func (t *Tracker) Report() *Report {
	if t == nil {
		return &Report{}
	}
	merged, replaced := t.collectRecords()

	removedPaths := make([]string, 0, len(t.shared.removed))
	for p := range t.shared.removed {
		removedPaths = append(removedPaths, p)
	}
	sort.Strings(removedPaths)
	removed := make([]ValueRecord, 0, len(removedPaths))
	for _, p := range removedPaths {
		n := t.shared.removed[p]
		sources := make([]ValueSource, 0, len(n.events))
		for _, ev := range n.events {
			if len(sources) > 0 && sources[len(sources)-1] == ev.src {
				continue
			}
			sources = append(sources, ev.src)
		}
		removed = append(removed, ValueRecord{
			Path:    p,
			Sources: sources,
			Final:   sources[len(sources)-1],
			Deleted: true,
		})
	}

	conflicts := append([]TypeConflict(nil), t.shared.conflicts...)
	sort.SliceStable(conflicts, func(i, j int) bool {
		if conflicts[i].Path == conflicts[j].Path {
			return conflicts[i].Message < conflicts[j].Message
		}
		return conflicts[i].Path < conflicts[j].Path
	})

	notes := t.locationNotes()

	return &Report{
		Merged:    merged,
		Replaced:  replaced,
		Removed:   removed,
		Conflicts: conflicts,
		Notes:     notes,
	}
}

func (t *Tracker) locationNotes() []string {
	seen := map[string]bool{}
	var notes []string
	for _, loc := range t.shared.locations {
		if seen[loc] {
			continue
		}
		seen[loc] = true
		if _, err := os.Stat(loc); err != nil {
			notes = append(notes, fmt.Sprintf("source location not accessible: %s", loc))
		}
	}
	sort.Strings(notes)
	return notes
}

const reportValuePreviewLimit = 80

func valuePreview(v any) string {
	if v == nil {
		return "null"
	}
	b, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > reportValuePreviewLimit {
		s = s[:reportValuePreviewLimit] + "..."
	}
	return s
}

func formatChain(r ValueRecord) string {
	var b strings.Builder
	for i := len(r.Sources) - 1; i >= 0; i-- {
		fmt.Fprintf(&b, " <- %s", r.Sources[i])
	}
	return b.String()
}

// String renders the report in the fixed output order:
// deep-merged leaves, wholesale replaced scalars/arrays, removed keys,
// type conflicts, notes.
func (r *Report) String() string {
	if r == nil {
		return ""
	}
	if len(r.Merged) == 0 && len(r.Replaced) == 0 && len(r.Removed) == 0 &&
		len(r.Conflicts) == 0 && len(r.Notes) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("VALUE SOURCE REPORT\n")
	if len(r.Merged) > 0 {
		b.WriteString("Effective values (deep-merged tables):\n")
		for _, rec := range r.Merged {
			fmt.Fprintf(&b, "  %s = %s%s\n", rec.Path, valuePreview(rec.Value), formatChain(rec))
		}
	}
	if len(r.Replaced) > 0 {
		b.WriteString("Effective values (replaced scalars and arrays):\n")
		for _, rec := range r.Replaced {
			fmt.Fprintf(&b, "  %s = %s%s\n", rec.Path, valuePreview(rec.Value), formatChain(rec))
		}
	}
	if len(r.Removed) > 0 {
		b.WriteString("Removed values (null):\n")
		for _, rec := range r.Removed {
			fmt.Fprintf(&b, "  %s (removed)%s\n", rec.Path, formatChain(rec))
		}
	}
	if len(r.Conflicts) > 0 {
		b.WriteString("Type conflicts:\n")
		for _, c := range r.Conflicts {
			fmt.Fprintf(&b, "  %s: %s: kept %s from %s, dropped %s from %s\n",
				c.Path, c.Message, c.KeptType, c.Kept, c.DroppedType, c.Dropped)
		}
	}
	if len(r.Notes) > 0 {
		b.WriteString("Notes:\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "  %s\n", n)
		}
	}
	return b.String()
}
