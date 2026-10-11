// Copyright The Helm Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package helmpath calculates filesystem paths to Helm's configuration, cache and data.
package helmpath

// This helper builds paths to Helm's configuration, cache and data paths.
const lp = lazypath("helm")

// ConfigPath returns the path where Helm stores configuration.
func ConfigPath(elem ...string) string { return lp.configPath(elem...) }

// ConfigPathOrigin works like ConfigPath but additionally reports where the
// base directory originated (HELM_CONFIG_HOME, XDG_CONFIG_HOME or the built-in
// operating system default).
func ConfigPathOrigin(elem ...string) (string, PathOrigin) { return lp.configPathOrigin(elem...) }

// CachePath returns the path where Helm stores cached objects.
func CachePath(elem ...string) string { return lp.cachePath(elem...) }

// CachePathOrigin works like CachePath but additionally reports where the
// base directory originated (HELM_CACHE_HOME, XDG_CACHE_HOME or the built-in
// operating system default).
func CachePathOrigin(elem ...string) (string, PathOrigin) { return lp.cachePathOrigin(elem...) }

// DataPath returns the path where Helm stores data.
func DataPath(elem ...string) string { return lp.dataPath(elem...) }

// DataPathOrigin works like DataPath but additionally reports where the
// base directory originated (HELM_DATA_HOME, XDG_DATA_HOME or the built-in
// operating system default).
func DataPathOrigin(elem ...string) (string, PathOrigin) { return lp.dataPathOrigin(elem...) }

// CacheIndexFile returns the path to an index for the given named repository.
func CacheIndexFile(name string) string {
	if name != "" {
		name += "-"
	}
	return name + "index.yaml"
}

// CacheChartsFile returns the path to a text file listing all the charts
// within the given named repository.
func CacheChartsFile(name string) string {
	if name != "" {
		name += "-"
	}
	return name + "charts.txt"
}
