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
	"log"
	"maps"

	"helm.sh/helm/v4/internal/copystructure"
	chart "helm.sh/helm/v4/pkg/chart"
	"helm.sh/helm/v4/pkg/chart/common"
)

func concatPrefix(a, b string) string {
	if a == "" {
		return b
	}
	return fmt.Sprintf("%s.%s", a, b)
}

// CoalesceValues coalesces all of the values in a chart (and its subcharts).
//
// Values are coalesced together using the following rules:
//
//   - Values in a higher level chart always override values in a lower-level
//     dependency chart
//   - Scalar values and arrays are replaced, maps are merged
//   - A chart has access to all of the variables for it, as well as all of
//     the values destined for its dependencies.
func CoalesceValues(chrt chart.Charter, vals map[string]any) (common.Values, error) {
	valsCopy, err := copyValues(vals)
	if err != nil {
		return vals, err
	}
	return coalesce(log.Printf, chrt, valsCopy, "", false, nil, nil, "")
}

// CoalesceValuesWithProvenance behaves like CoalesceValues but records the
// source of every effective leaf on t. The caller must have built t's root
// shadow (e.g. through the tracked CLI value merge) so that it mirrors vals;
// an empty root is valid when vals is nil/empty.
func CoalesceValuesWithProvenance(chrt chart.Charter, vals map[string]any, t *Tracker) (common.Values, error) {
	valsCopy, err := copyValues(vals)
	if err != nil {
		return vals, err
	}
	t.DeepCopyRoot()
	out, err := coalesce(log.Printf, chrt, valsCopy, "", false, t, t.Root(), "")
	if err == nil {
		t.lastValues = out
	}
	return out, err
}

// MergeValues is used to merge the values in a chart and its subcharts. This
// is different from Coalescing as nil/null values are preserved.
//
// Values are coalesced together using the following rules:
//
//   - Values in a higher level chart always override values in a lower-level
//     dependency chart
//   - Scalar values and arrays are replaced, maps are merged
//   - A chart has access to all of the variables for it, as well as all of
//     the values destined for its dependencies.
//
// Retaining Nils is useful when processes early in a Helm action or business
// logic need to retain them for when Coalescing will happen again later in the
// business logic.
func MergeValues(chrt chart.Charter, vals map[string]any) (common.Values, error) {
	valsCopy, err := copyValues(vals)
	if err != nil {
		return vals, err
	}
	return coalesce(log.Printf, chrt, valsCopy, "", true, nil, nil, "")
}

// MergeValuesWithProvenance behaves like MergeValues but records sources on t.
// The resulting shadow tree is available via t.Root().
func MergeValuesWithProvenance(chrt chart.Charter, vals map[string]any, t *Tracker) (common.Values, error) {
	valsCopy, err := copyValues(vals)
	if err != nil {
		return vals, err
	}
	if t.Root() == nil {
		t.SetRoot(nil)
	}
	t.DeepCopyRoot()
	out, err := coalesce(log.Printf, chrt, valsCopy, "", true, t, t.Root(), "")
	if err == nil {
		t.lastValues = out
	}
	return out, err
}

func copyValues(vals map[string]any) (common.Values, error) {
	v, err := copystructure.Copy(vals)
	if err != nil {
		return vals, err
	}

	valsCopy := v.(map[string]any)
	// if we have an empty map, make sure it is initialized
	if valsCopy == nil {
		valsCopy = make(map[string]any)
	}

	return valsCopy, nil
}

type printFn func(format string, v ...any)

// coalesce coalesces the dest values and the chart values, giving priority to the dest values.
//
// This is a helper function for CoalesceValues and MergeValues.
//
// Note, the merge argument specifies whether this is being used by MergeValues
// or CoalesceValues. Coalescing removes null values and their keys in some
// situations while merging keeps the null values.
//
// When t is non-nil, destN is the provenance shadow mirroring dest and
// sprefix is the structural (map-key based) dotted path of dest.
func coalesce(printf printFn, ch chart.Charter, dest map[string]any, prefix string, merge bool, t *Tracker, destN *ProvNode, sprefix string) (map[string]any, error) {
	coalesceValues(printf, ch, dest, prefix, merge, t, destN, sprefix)
	return coalesceDeps(printf, ch, dest, prefix, merge, t, destN, sprefix)
}

// coalesceDeps coalesces the dependencies of the given chart.
func coalesceDeps(printf printFn, chrt chart.Charter, dest map[string]any, prefix string, merge bool, t *Tracker, destN *ProvNode, sprefix string) (map[string]any, error) {
	ch, err := chart.NewAccessor(chrt)
	if err != nil {
		return dest, err
	}
	for _, subchart := range ch.Dependencies() {
		sub, err := chart.NewAccessor(subchart)
		if err != nil {
			return dest, err
		}
		if c, ok := dest[sub.Name()]; !ok {
			// If dest doesn't already have the key, create it.
			dest[sub.Name()] = make(map[string]any)
			if t != nil && destN != nil {
				destN.ensureChildren()[sub.Name()] = newProvNode()
			}
		} else if !istable(c) {
			return dest, fmt.Errorf("type mismatch on %s: %t", sub.Name(), c)
		}
		if dv, ok := dest[sub.Name()]; ok {
			dvmap := dv.(map[string]any)
			subPrefix := concatPrefix(prefix, ch.Name())
			subSPrefix := concatPrefix(sprefix, sub.Name())
			var dvN *ProvNode
			if destN != nil {
				dvN = destN.children[sub.Name()]
			}
			// Get globals out of dest and merge them into dvmap.
			coalesceGlobals(printf, dvmap, dest, subPrefix, merge, t, dvN, destN, subSPrefix)
			// Values the parent chart's defaults supply for a dependency are
			// parent overrides from the child chart's point of view.
			if t != nil && dvN != nil {
				retagParentOverrides(dvN)
			}
			// Now coalesce the rest of the values.
			dest[sub.Name()], err = coalesce(printf, subchart, dvmap, subPrefix, merge, t, dvN, subSPrefix)
			if err != nil {
				return dest, err
			}
		}
	}
	return dest, nil
}

// retagParentOverrides relabels trailing chart-default events (the parent
// chart's values.yaml) below n, excluding the globals subtree (handled by
// coalesceGlobals), as parent overrides. Events from other sources are left
// untouched.
func retagParentOverrides(n *ProvNode) {
	if n == nil {
		return
	}
	for k, child := range n.children {
		if k == common.GlobalKey {
			continue
		}
		retagTrailingCategory(child, SourceChartDefault, SourceParentOverride)
	}
}

// retagTrailingCategory walks leaves and replaces the trailing event category
// when it equals from.
func retagTrailingCategory(n *ProvNode, from, to SourceCategory) {
	if n == nil {
		return
	}
	if n.isLeaf() {
		if len(n.events) > 0 && n.events[len(n.events)-1].src.Category == from {
			n.events[len(n.events)-1].src.Category = to
		}
		return
	}
	for _, child := range n.children {
		retagTrailingCategory(child, from, to)
	}
}

// coalesceGlobals copies the globals out of src and merges them into dest.
//
// For convenience, returns dest.
func coalesceGlobals(printf printFn, dest, src map[string]any, prefix string, _ bool, t *Tracker, destN, srcN *ProvNode, sprefix string) {
	var dg, sg map[string]any

	if destglob, ok := dest[common.GlobalKey]; !ok {
		dg = make(map[string]any)
	} else if dg, ok = destglob.(map[string]any); !ok {
		printf("warning: skipping globals because destination %s is not a table.", common.GlobalKey)
		return
	}

	if srcglob, ok := src[common.GlobalKey]; !ok {
		sg = make(map[string]any)
	} else if sg, ok = srcglob.(map[string]any); !ok {
		printf("warning: skipping globals because source %s is not a table.", common.GlobalKey)
		return
	}

	var dgN, sgN *ProvNode
	if t != nil {
		if destN != nil {
			dgN = destN.children[common.GlobalKey]
		}
		if dgN == nil {
			dgN = newProvNode()
		}
		if srcN != nil {
			sgN = srcN.children[common.GlobalKey]
		}
	}

	// EXPERIMENTAL: In the past, we have disallowed globals to test tables. This
	// reverses that decision. It may somehow be possible to introduce a loop
	// here, but I haven't found a way. So for the time being, let's allow
	// tables in globals.
	for key, val := range sg {
		if istable(val) {
			vv := copyMap(val.(map[string]any))
			if destv, ok := dg[key]; !ok {
				// Here there is no merge. We're just adding.
				dg[key] = vv
				if t != nil {
					var vvN *ProvNode
					if sgN != nil {
						vvN = sgN.children[key].clone()
					} else {
						vvN = newProvNode()
					}
					tagGlobalLeaves(vvN)
					dgN.ensureChildren()[key] = vvN
				}
			} else {
				if destvmap, ok := destv.(map[string]any); !ok {
					printf("Conflict: cannot merge map onto non-map for %q. Skipping.", key)
					if t != nil {
						t.conflict(concatPrefix(sprefix, concatPrefix(common.GlobalKey, key)),
							"cannot merge global table onto non-table",
							dgN.children[key], nodeChild(sgN, key), destv, val)
					}
				} else {
					// Basically, we reverse order of coalesce here to merge
					// top-down.
					subPrefix := concatPrefix(prefix, key)
					// In this location coalesceTablesFullKey should always have
					// merge set to true. The output of coalesceGlobals is run
					// through coalesce where any nils will be removed.
					var vvN, destvN *ProvNode
					if t != nil {
						if sgN != nil {
							vvN = sgN.children[key].clone()
						} else {
							vvN = newProvNode()
						}
						tagGlobalLeaves(vvN)
						destvN = dgN.children[key]
					}
					coalesceTablesFullKey(printf, vv, destvmap, subPrefix, true, t, vvN, destvN,
						concatPrefix(sprefix, concatPrefix(common.GlobalKey, key)))
					dg[key] = vv
					if t != nil {
						dgN.ensureChildren()[key] = vvN
					}
				}
			}
		} else if dv, ok := dg[key]; ok && istable(dv) {
			// It's not clear if this condition can actually ever trigger.
			printf("key %s is table. Skipping", key)
			if t != nil {
				t.conflict(concatPrefix(sprefix, concatPrefix(common.GlobalKey, key)),
					"global destination is a table; skipping non-table global",
					dgN.children[key], nodeChild(sgN, key), dv, val)
			}
		} else {
			// TODO: Do we need to do any additional checking on the value?
			dg[key] = val
			if t != nil {
				gsp := concatPrefix(sprefix, concatPrefix(common.GlobalKey, key))
				sn := globalLeafNode(nodeChild(sgN, key))
				if dn, ok := dgN.children[key]; ok && dn != nil {
					dgN.children[key] = joinNodes(dn, sn)
					t.conflict(gsp, "global value replaces non-table value",
						sn, dn, val, dv)
				} else {
					dgN.ensureChildren()[key] = sn
				}
			}
		}
	}
	dest[common.GlobalKey] = dg
	if t != nil && destN != nil {
		destN.ensureChildren()[common.GlobalKey] = dgN
	}
}

// nodeChild returns a child node without forcing creation.
func nodeChild(n *ProvNode, key string) *ProvNode {
	if n == nil || n.children == nil {
		return nil
	}
	return n.children[key]
}

// globalLeafNode clones a node and appends a global propagation event to
// every leaf, using the leaf's own origin location.
func globalLeafNode(n *ProvNode) *ProvNode {
	c := n.clone()
	tagGlobalLeaves(c)
	return c
}

// tagGlobalLeaves appends a SourceGlobal event to each leaf below n. The
// event location points at the leaf's originating source location.
func tagGlobalLeaves(n *ProvNode) {
	if n == nil {
		return
	}
	if n.isLeaf() {
		loc := n.lastEvent().src.Location
		appendEvents(n, provEvent{src: ValueSource{Category: SourceGlobal, Location: loc}, op: opMerge})
		return
	}
	for _, child := range n.children {
		tagGlobalLeaves(child)
	}
}

func copyMap(src map[string]any) map[string]any {
	m := make(map[string]any, len(src))
	maps.Copy(m, src)
	return m
}

// coalesceValues builds up a values map for a particular chart.
//
// Values in v will override the values in the chart.
func coalesceValues(printf printFn, c chart.Charter, v map[string]any, prefix string, merge bool, t *Tracker, vN *ProvNode, sprefix string) {
	ch, err := chart.NewAccessor(c)
	if err != nil {
		return
	}

	subPrefix := concatPrefix(prefix, ch.Name())
	// Structural paths mirror the values map keys, which do not carry the
	// chart name; subchart sections are already keyed by the dependency name.
	subSPrefix := sprefix

	// Using c.Values directly when coalescing a table can cause problems where
	// the original c.Values is altered. Creating a deep copy stops the problem.
	// This section is fault-tolerant as there is no ability to return an error.
	valuesCopy, err := copystructure.Copy(ch.Values())
	var vc map[string]any
	var ok bool
	if err != nil {
		// If there is an error something is wrong with copying c.Values it
		// means there is a problem in the deep copying package or something
		// wrong with c.Values. In this case we will use c.Values and report
		// an error.
		printf("warning: unable to copy values, err: %s", err)
		vc = ch.Values()
	} else {
		vc, ok = valuesCopy.(map[string]any)
		if !ok {
			// c.Values has a map[string]interface{} structure. If the copy of
			// it cannot be treated as map[string]interface{} there is something
			// strangely wrong. Log it and use c.Values
			printf("warning: unable to convert values copy to values type")
			vc = ch.Values()
		}
	}

	// Build the shadow mirroring the chart defaults, unless an earlier tracked
	// stage (import-values, reused values) registered one for this chart.
	var vcN *ProvNode
	if t != nil {
		if reg, ok := t.ChartShadow(c); ok {
			vcN = reg.clone()
		} else {
			vcN = t.ShadowForMap(vc, ValueSource{Category: SourceChartDefault, Location: chartValuesLocation(c)})
		}
	}

	for key, val := range vc {
		if value, ok := v[key]; ok {
			if value == nil && !merge {
				// When the YAML value is null and we are coalescing instead of
				// merging, we remove the value's key.
				// This allows Helm's various sources of values (value files or --set) to
				// remove incompatible keys from any previous chart, file, or set values.
				delete(v, key)
				if t != nil {
					recordCoalesceRemoval(t, vN, vcN, key, concatPrefix(subSPrefix, key))
					if vN != nil && vN.children != nil {
						delete(vN.children, key)
					}
				}
			} else if dest, ok := value.(map[string]any); ok {
				// if v[key] is a table, merge nv's val table into v[key].
				src, ok := val.(map[string]any)
				if !ok {
					// If the original value is nil, there is nothing to coalesce, so we don't print
					// the warning
					if val != nil {
						printf("warning: skipped value for %s.%s: Not a table.", subPrefix, key)
						if t != nil {
							t.conflict(concatPrefix(subSPrefix, key),
								"cannot merge chart default non-table into table",
								nodeChild(vN, key), nodeChild(vcN, key), value, val)
						}
					}
				} else {
					// If the key is a child chart, coalesce tables with Merge set to true
					merge := childChartMergeTrue(c, key, merge)

					srcN := nodeChild(vcN, key)
					// When coalescing, clean nils from chart defaults before merging
					// so they don't leak into the result.
					if !merge {
						cleanNilValues(src, t, srcN)
					}

					// Because v has higher precedence than nv, dest values override src
					// values.
					coalesceTablesFullKey(printf, dest, src, concatPrefix(subPrefix, key), merge, t,
						nodeChild(vN, key), srcN, concatPrefix(subSPrefix, key))
				}
			} else if t != nil && value != nil && val != nil {
				// Scalar/array in dest wins silently over a scalar/array chart
				// default; record the override chain for diagnostics.
				if dn, sn := nodeChild(vN, key), nodeChild(vcN, key); dn != nil && sn != nil {
					vN.ensureChildren()[key] = joinNodes(sn, dn)
					t.conflict(concatPrefix(subSPrefix, key),
						"value replaces chart default of different type",
						dn, sn, value, val)
				}
			}
		} else {
			// If the key is not in v, copy it from nv.
			// When coalescing, skip chart default nils and clean nils from
			// nested maps so they don't shadow globals or produce %!s(<nil>).
			if !merge {
				if val == nil {
					continue
				}
				if sub, ok := val.(map[string]any); ok {
					cleanNilValues(sub, t, nodeChild(vcN, key))
				}
			}
			v[key] = val
			if t != nil && vN != nil {
				if sn := nodeChild(vcN, key); sn != nil {
					vN.ensureChildren()[key] = sn.clone()
				}
			}
		}
	}
}

// recordCoalesceRemoval records a key nullified by a dest nil on the removal
// list, keeping the overridden non-nil chart default in the chain. When a whole
// table default is nullified, its leaves are recorded individually too.
func recordCoalesceRemoval(t *Tracker, vN, vcN *ProvNode, key, fullKey string) {
	dn := nodeChild(vN, key)
	sn := nodeChild(vcN, key)
	var n *ProvNode
	switch {
	case sn != nil && dn != nil:
		n = joinNodes(sn, dn)
	case dn != nil:
		n = dn.clone()
	case sn != nil:
		n = sn.clone()
	default:
		n = newProvNode()
		appendEvents(n, provEvent{op: opDelete, typ: "null"})
	}
	if len(n.events) > 0 {
		n.events[len(n.events)-1].op = opDelete
		n.events[len(n.events)-1].typ = "null"
	}
	t.recordRemoved(fullKey, n)

	if sn != nil && !sn.isLeaf() {
		recordRemovedTableLeaves(t, sn, dn, fullKey)
	}
}

// recordRemovedTableLeaves records every leaf of a nullified default table.
func recordRemovedTableLeaves(t *Tracker, tableN, nullifier *ProvNode, prefix string) {
	keys := make([]string, 0, len(tableN.children))
	for k := range tableN.children {
		keys = append(keys, k)
	}
	for _, k := range keys {
		child := tableN.children[k]
		full := concatPrefix(prefix, k)
		if child.isLeaf() {
			n := child.clone()
			if nullifier != nil {
				n = joinNodes(n, nullifier)
			}
			if len(n.events) > 0 {
				n.events[len(n.events)-1].op = opDelete
				n.events[len(n.events)-1].typ = "null"
			}
			t.recordRemoved(full, n)
			continue
		}
		recordRemovedTableLeaves(t, child, nullifier, full)
	}
}

func childChartMergeTrue(chrt chart.Charter, key string, merge bool) bool {
	ch, err := chart.NewAccessor(chrt)
	if err != nil {
		return merge
	}
	for _, subchart := range ch.Dependencies() {
		sub, err := chart.NewAccessor(subchart)
		if err != nil {
			return merge
		}
		if sub.Name() == key {
			return true
		}
	}
	return merge
}

// CoalesceTables merges a source map into a destination map.
//
// dest is considered authoritative.
func CoalesceTables(dst, src map[string]any) map[string]any {
	return coalesceTablesFullKey(log.Printf, dst, src, "", false, nil, nil, nil, "")
}

func MergeTables(dst, src map[string]any) map[string]any {
	return coalesceTablesFullKey(log.Printf, dst, src, "", true, nil, nil, nil, "")
}

// CoalesceTablesTracked mirrors coalesceTablesFullKey while recording sources.
// dstN/srcN shadow dst/src; the returned node is the merged shadow. Prefix is
// the structural dotted path of dst/src and is used for conflict and removal
// records.
func (t *Tracker) CoalesceTablesTracked(dst, src map[string]any, dstN, srcN *ProvNode, prefix string, merge bool) (map[string]any, *ProvNode) {
	if dstN == nil {
		dstN = newProvNode()
	}
	if srcN == nil {
		srcN = newProvNode()
	}
	out := coalesceTablesFullKey(log.Printf, dst, src, prefix, merge, t, dstN, srcN, prefix)
	return out, dstN
}

// coalesceTablesFullKey merges a source map into a destination map.
//
// dest is considered authoritative.
func coalesceTablesFullKey(printf printFn, dst, src map[string]any, prefix string, merge bool, t *Tracker, dstN, srcN *ProvNode, sprefix string) map[string]any {
	// When --reuse-values is set but there are no modifications yet, return new values
	if src == nil {
		return dst
	}
	if dst == nil {
		return src
	}
	// Track original non-nil src keys before modifying src
	// This lets us distinguish between user nullifying a chart default vs
	// user setting nil for a key not in chart defaults.
	srcOriginalNonNil := make(map[string]bool)
	for key, val := range src {
		if val != nil {
			srcOriginalNonNil[key] = true
		}
	}
	for key, val := range dst {
		if val == nil {
			src[key] = nil
			if t != nil {
				if dn := nodeChild(dstN, key); dn != nil {
					if srcN != nil {
						srcN.ensureChildren()[key] = dn.clone()
					}
				}
			}
		}
	}
	// Because dest has higher precedence than src, dest values override src
	// values.
	for key, val := range src {
		fullkey := concatPrefix(prefix, key)
		fullSKey := concatPrefix(sprefix, key)
		dv, ok := dst[key]
		dn := nodeChild(dstN, key)
		sn := nodeChild(srcN, key)
		switch {
		case ok && !merge && dv == nil && srcOriginalNonNil[key]:
			// When coalescing (not merging), if dst has nil and src has a non-nil
			// value, the user is nullifying a chart default - remove the key.
			// But if src also has nil (or key not in src), preserve the nil
			delete(dst, key)
			if t != nil {
				n := joinNodes(sn, dn)
				if len(n.events) > 0 {
					n.events[len(n.events)-1].op = opDelete
					n.events[len(n.events)-1].typ = "null"
				}
				t.recordRemoved(fullSKey, n)
				if sn != nil && !sn.isLeaf() {
					recordRemovedTableLeaves(t, sn, dn, fullSKey)
				}
				if dstN != nil {
					delete(dstN.children, key)
				}
			}
		case !ok:
			dst[key] = val
			if t != nil && dstN != nil && sn != nil {
				dstN.ensureChildren()[key] = sn.clone()
			}
		case istable(val):
			if istable(dv) {
				coalesceTablesFullKey(printf, dv.(map[string]any), val.(map[string]any), fullkey, merge, t, dn, sn, fullSKey)
			} else {
				printf("warning: cannot overwrite table with non table for %s (%v)", fullkey, val)
				if t != nil {
					t.conflict(fullSKey, "cannot overwrite table with non-table",
						dn, sn, dv, val)
				}
			}
		case istable(dv) && val != nil:
			printf("warning: destination for %s is a table. Ignoring non-table value (%v)", fullkey, val)
			if t != nil {
				t.conflict(fullSKey, "destination is a table; ignoring non-table value",
					dn, sn, dv, val)
			}
		default:
			// Both sides hold scalars/arrays (or merge-mode nils): dest stays
			// authoritative, but the chain records the overridden source.
			if t != nil && ok && val != nil && dv != nil && dn != nil && sn != nil {
				dstN.ensureChildren()[key] = joinNodes(sn, dn)
				t.conflict(fullSKey, "value replaces previous value of different type",
					dn, sn, dv, val)
			}
		}
	}
	return dst
}

// cleanNilValues recursively removes nil entries in-place from a map so that chart
// default nils don't leak into the coalesced result.
func cleanNilValues(m map[string]any, t *Tracker, n *ProvNode) {
	for key, val := range m {
		if val == nil {
			delete(m, key)
			if t != nil && n != nil && n.children != nil {
				delete(n.children, key)
			}
		} else if sub, ok := val.(map[string]any); ok {
			cleanNilValues(sub, t, nodeChild(n, key))
		}
	}
}

// istable is a special-purpose function to see if the present thing matches the definition of a YAML table.
func istable(v any) bool {
	_, ok := v.(map[string]any)
	return ok
}
