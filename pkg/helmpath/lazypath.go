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

package helmpath

import (
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"helm.sh/helm/v4/pkg/helmpath/xdg"
)

const (
	// CacheHomeEnvVar is the environment variable used by Helm
	// for the cache directory. When no value is set a default is used.
	CacheHomeEnvVar = "HELM_CACHE_HOME"

	// ConfigHomeEnvVar is the environment variable used by Helm
	// for the config directory. When no value is set a default is used.
	ConfigHomeEnvVar = "HELM_CONFIG_HOME"

	// DataHomeEnvVar is the environment variable used by Helm
	// for the data directory. When no value is set a default is used.
	DataHomeEnvVar = "HELM_DATA_HOME"
)

// BaseSource identifies where a lazypath base directory came from.
type BaseSource int

const (
	// BaseSourceDefault means the operating system specific default base
	// directory is used because neither the Helm specific nor the XDG base
	// directory environment variable was set to a non-empty value.
	BaseSourceDefault BaseSource = iota
	// BaseSourceHelmEnv means the HELM_*_HOME environment variable provided
	// the base directory.
	BaseSourceHelmEnv
	// BaseSourceXDGEnv means the XDG_*_HOME environment variable provided the
	// base directory.
	BaseSourceXDGEnv
)

// PathOrigin describes how a lazypath path was resolved.
type PathOrigin struct {
	// Path is the resolved path. It is identical to the value returned by the
	// corresponding ConfigPath/CachePath/DataPath call.
	Path string
	// Source identifies which kind of source provided Base.
	Source BaseSource
	// EnvVar is the name of the environment variable that provided Base. It
	// is empty when Source is BaseSourceDefault.
	EnvVar string
	// Base is the base directory the resolved path is relative to.
	Base string
	// DefaultBase is the operating system specific default base directory.
	DefaultBase string
	// DefaultPath is the path that would be resolved if neither the Helm
	// specific nor the XDG base directory environment variable was set.
	DefaultPath string
}

// IsBlankPath reports whether p contains no path component, i.e. it is empty
// or consists solely of path separators and whitespace. Such values are
// treated as unset so that no empty path is produced.
func IsBlankPath(p string) bool {
	return strings.TrimFunc(p, func(r rune) bool {
		return unicode.IsSpace(r) || r == '/' || r == filepath.Separator
	}) == ""
}

// lazypath is a lazy-loaded path buffer for the XDG base directory specification.
type lazypath string

func (l lazypath) path(helmEnvVar, xdgEnvVar string, defaultFn func() string, elem ...string) string {
	path, _ := l.pathOrigin(helmEnvVar, xdgEnvVar, defaultFn, elem...)
	return path
}

// pathOrigin resolves a path exactly like path, but additionally reports where
// the base directory originated.
func (l lazypath) pathOrigin(helmEnvVar, xdgEnvVar string, defaultFn func() string, elem ...string) (string, PathOrigin) {
	// There is an order to checking for a path.
	// 1. See if a Helm specific environment variable has been set.
	// 2. Check if an XDG environment variable is set
	// 3. Fall back to a default
	defBase := defaultFn()
	origin := PathOrigin{
		Source:      BaseSourceDefault,
		Base:        defBase,
		DefaultBase: defBase,
	}
	origin.DefaultPath = filepath.Join(defBase, string(l), filepath.Join(elem...))
	origin.Path = origin.DefaultPath

	// A value that is empty or made up solely of separators and whitespace is
	// treated as unset so that no empty path is produced.
	if base := os.Getenv(helmEnvVar); !IsBlankPath(base) {
		origin.Source = BaseSourceHelmEnv
		origin.EnvVar = helmEnvVar
		origin.Base = base
		origin.Path = filepath.Join(base, filepath.Join(elem...))
		return origin.Path, origin
	}

	if base := os.Getenv(xdgEnvVar); !IsBlankPath(base) {
		origin.Source = BaseSourceXDGEnv
		origin.EnvVar = xdgEnvVar
		origin.Base = base
		origin.Path = filepath.Join(base, string(l), filepath.Join(elem...))
		return origin.Path, origin
	}

	return origin.Path, origin
}

// cachePath defines the base directory relative to which user specific non-essential data files
// should be stored.
func (l lazypath) cachePath(elem ...string) string {
	return l.path(CacheHomeEnvVar, xdg.CacheHomeEnvVar, cacheHome, filepath.Join(elem...))
}

// cachePathOrigin works like cachePath but also reports the origin of the base directory.
func (l lazypath) cachePathOrigin(elem ...string) (string, PathOrigin) {
	return l.pathOrigin(CacheHomeEnvVar, xdg.CacheHomeEnvVar, cacheHome, filepath.Join(elem...))
}

// configPath defines the base directory relative to which user specific configuration files should
// be stored.
func (l lazypath) configPath(elem ...string) string {
	return l.path(ConfigHomeEnvVar, xdg.ConfigHomeEnvVar, configHome, filepath.Join(elem...))
}

// configPathOrigin works like configPath but also reports the origin of the base directory.
func (l lazypath) configPathOrigin(elem ...string) (string, PathOrigin) {
	return l.pathOrigin(ConfigHomeEnvVar, xdg.ConfigHomeEnvVar, configHome, filepath.Join(elem...))
}

// dataPath defines the base directory relative to which user specific data files should be stored.
func (l lazypath) dataPath(elem ...string) string {
	return l.path(DataHomeEnvVar, xdg.DataHomeEnvVar, dataHome, filepath.Join(elem...))
}

// dataPathOrigin works like dataPath but also reports the origin of the base directory.
func (l lazypath) dataPathOrigin(elem ...string) (string, PathOrigin) {
	return l.pathOrigin(DataHomeEnvVar, xdg.DataHomeEnvVar, dataHome, filepath.Join(elem...))
}
