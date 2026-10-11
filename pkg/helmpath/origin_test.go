// Copyright The Helm Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helmpath

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"helm.sh/helm/v4/pkg/helmpath/xdg"
)

func TestPathOrigin(t *testing.T) {
	t.Run("helm env var wins over xdg", func(t *testing.T) {
		t.Setenv(CacheHomeEnvVar, filepath.FromSlash("/helm/cache"))
		t.Setenv(xdg.CacheHomeEnvVar, filepath.FromSlash("/xdg/cache"))

		path, origin := CachePathOrigin("repository")
		assert.Equal(t, CachePath("repository"), path)
		assert.Equal(t, BaseSourceHelmEnv, origin.Source)
		assert.Equal(t, CacheHomeEnvVar, origin.EnvVar)
		assert.Equal(t, filepath.Join(filepath.FromSlash("/helm/cache"), "repository"), path)
		assert.NotEmpty(t, origin.DefaultPath)
		assert.NotEmpty(t, origin.DefaultBase)
	})

	t.Run("xdg env var is used when helm var is unset", func(t *testing.T) {
		t.Setenv(CacheHomeEnvVar, "")
		t.Setenv(xdg.CacheHomeEnvVar, filepath.FromSlash("/xdg/cache"))

		path, origin := CachePathOrigin("repository")
		assert.Equal(t, CachePath("repository"), path)
		assert.Equal(t, BaseSourceXDGEnv, origin.Source)
		assert.Equal(t, xdg.CacheHomeEnvVar, origin.EnvVar)
		assert.Equal(t, filepath.Join(filepath.FromSlash("/xdg/cache"), "helm", "repository"), path)
	})

	t.Run("blank helm env var falls through to xdg", func(t *testing.T) {
		t.Setenv(CacheHomeEnvVar, "  /  ")
		t.Setenv(xdg.CacheHomeEnvVar, filepath.FromSlash("/xdg/cache"))

		path, origin := CachePathOrigin("repository")
		assert.Equal(t, BaseSourceXDGEnv, origin.Source)
		assert.Equal(t, filepath.Join(filepath.FromSlash("/xdg/cache"), "helm", "repository"), path)
		assert.Equal(t, path, CachePath("repository"))
	})

	t.Run("blank helm and xdg env vars fall through to the default", func(t *testing.T) {
		t.Setenv(ConfigHomeEnvVar, string(filepath.Separator))
		t.Setenv(xdg.ConfigHomeEnvVar, "\t ")

		path, origin := ConfigPathOrigin("repositories.yaml")
		assert.Equal(t, BaseSourceDefault, origin.Source)
		assert.Empty(t, origin.EnvVar)
		assert.Equal(t, origin.DefaultPath, path)
		assert.Equal(t, ConfigPath("repositories.yaml"), path)
	})

	t.Run("default origin is reported when nothing is set", func(t *testing.T) {
		t.Setenv(DataHomeEnvVar, "")
		t.Setenv(xdg.DataHomeEnvVar, "")

		path, origin := DataPathOrigin("plugins")
		require.Equal(t, BaseSourceDefault, origin.Source)
		assert.Equal(t, origin.DefaultPath, path)
		assert.Equal(t, DataPath("plugins"), path)
		assert.Equal(t, filepath.Join(origin.DefaultBase, "helm", "plugins"), origin.DefaultPath)
	})
}

func TestIsBlankPath(t *testing.T) {
	for _, p := range []string{"", " ", "\t", "/", "\\", " / \\ ", string(filepath.Separator)} {
		assert.True(t, IsBlankPath(p), "expected %q to be blank", p)
	}
	for _, p := range []string{"/tmp", "tmp", " /tmp", "C:\\helm", "./x", ".", ".."} {
		assert.False(t, IsBlankPath(p), "expected %q to be non-blank", p)
	}
}
