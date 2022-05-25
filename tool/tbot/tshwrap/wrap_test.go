/*
Copyright 2022 Gravitational, Inc.

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

package tshwrap

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/tool/tbot/config"
	"github.com/gravitational/teleport/tool/tbot/identity"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

// mockRunner is a mock tsh runner
type mockRunner struct {
	captureErr error
	captureOut []byte
}

func (r *mockRunner) Capture(args ...string) ([]byte, error) {
	if r.captureErr != nil {
		return nil, r.captureErr
	}
	return r.captureOut, nil
}

func (r *mockRunner) Exec(env map[string]string, args ...string) error {
	return trace.NotImplemented("not implemented")
}

// TestTSHSupported ensures that the tsh version check works as expected (and,
// implicitly, that the version capture and parsing works.)
func TestTSHSupported(t *testing.T) {
	version := func(v string) []byte {
		bytes, err := json.Marshal(struct {
			Version string `json:"version"`
		}{
			Version: v,
		})
		require.NoError(t, err)

		return bytes
	}

	tests := []struct {
		name   string
		out    []byte
		err    error
		expect func(t *testing.T, err error)
	}{
		{
			// Before `-f json` is supported
			name: "very old tsh",
			err:  trace.Errorf("unsupported"),
			expect: func(t *testing.T, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "too old",
			out:  version("9.2.0"),
			expect: func(t *testing.T, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "supported",
			out:  version(TSHMinVersion),
			expect: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &mockRunner{
				captureOut: tt.out,
				captureErr: tt.err,
			}

			tt.expect(t, CheckTSHSupported(runner))
		})
	}
}

// TestGetEnvForTSH ensures we generate a valid minimum subset of environment
// parameters needed for tsh wrappers to work.
func TestGetEnvForTSH(t *testing.T) {
	destination := config.DestinationConfig{
		DestinationMixin: config.DestinationMixin{
			Directory: &config.DestinationDirectory{
				Path: "/foo",
			},
		},
	}
	require.NoError(t, destination.CheckAndSetDefaults())

	p, err := GetDestinationPath(&destination)
	require.NoError(t, err)

	tlsCAs, err := GetTLSCATemplate(&destination)
	require.NoError(t, err)

	expected := map[string]string{
		client.VirtualPathEnvName(client.VirtualPathKey, nil):      filepath.Join(p, identity.PrivateKeyKey),
		client.VirtualPathEnvName(client.VirtualPathDatabase, nil): filepath.Join(p, identity.TLSCertKey),
		client.VirtualPathEnvName(client.VirtualPathApp, nil):      filepath.Join(p, identity.TLSCertKey),

		client.VirtualPathEnvName(client.VirtualPathCA, client.VirtualPathCAParams(types.UserCA)):     filepath.Join(p, tlsCAs.UserCAPath),
		client.VirtualPathEnvName(client.VirtualPathCA, client.VirtualPathCAParams(types.HostCA)):     filepath.Join(p, tlsCAs.HostCAPath),
		client.VirtualPathEnvName(client.VirtualPathCA, client.VirtualPathCAParams(types.DatabaseCA)): filepath.Join(p, tlsCAs.DatabaseCAPath),
	}

	env, err := GetEnvForTSH(&destination)
	require.NoError(t, err)
	for k, v := range expected {
		require.Contains(t, env, k)
		require.Equal(t, v, env[k])
	}
}

func TestGetDestinationPath(t *testing.T) {
	destination := config.DestinationConfig{
		DestinationMixin: config.DestinationMixin{
			Directory: &config.DestinationDirectory{
				Path: "/foo",
			},
		},
	}
	require.NoError(t, destination.CheckAndSetDefaults())

	path, err := GetDestinationPath(&destination)
	require.NoError(t, err)
	require.Equal(t, "/foo", path)
}

func TestGetIdentityTemplate(t *testing.T) {
	destination := config.DestinationConfig{
		DestinationMixin: config.DestinationMixin{
			Directory: &config.DestinationDirectory{
				Path: "/foo",
			},
		},
	}
	require.NoError(t, destination.CheckAndSetDefaults())

	tpl, err := GetIdentityTemplate(&destination)
	require.NoError(t, err)

	// We don't particularly care where the file goes, but it does need to be
	// set.
	require.NotEmpty(t, tpl.FileName)
}

func TestGetTLSCATemplate(t *testing.T) {
	destination := config.DestinationConfig{
		DestinationMixin: config.DestinationMixin{
			Directory: &config.DestinationDirectory{
				Path: "/foo",
			},
		},
	}
	require.NoError(t, destination.CheckAndSetDefaults())

	tpl, err := GetTLSCATemplate(&destination)
	require.NoError(t, err)

	// As above, the name is arbitrary but these do need to exist.
	require.NotEmpty(t, tpl.HostCAPath)
	require.NotEmpty(t, tpl.UserCAPath)
	require.NotEmpty(t, tpl.DatabaseCAPath)
}
