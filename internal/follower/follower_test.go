// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package follower

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pterm/pterm"
	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

func TestCheckRequirements(t *testing.T) {
	printer := output.NewPrinter(pterm.LogLevelDebug, pterm.LogFormatterJSON, os.Stdout)

	type testArtifact struct {
		conf          *oci.ArtifactConfig
		falcoVersions map[string]string
		expectErr     bool
		testName      string
	}
	var testArtifactConfigs = []testArtifact{
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version_semver", Version: "0.26.0"}},
			},
			falcoVersions: map[string]string{"engine_version_semver": "0.26.0", "engine_version": "26"},
			expectErr:     false,
			testName:      "New Falco with new rules with new semver engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version_semver", Version: "26"}},
			},
			falcoVersions: map[string]string{"engine_version_semver": "0.26.0", "engine_version": "26"},
			expectErr:     true,
			testName:      "New Falco with new rules with old int engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version_semver", Version: "0.26.0"}},
			},
			falcoVersions: map[string]string{"engine_version": "26"},
			expectErr:     true,
			testName:      "Old Falco with new rules with new semver engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version_semver", Version: "26"}},
			},
			falcoVersions: map[string]string{"engine_version": "26"},
			expectErr:     true,
			testName:      "Old Falco with new new rules with old int engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version", Version: "26"}},
			},
			falcoVersions: map[string]string{"engine_version_semver": "0.26.0", "engine_version": "26"},
			expectErr:     false,
			testName:      "New Falco with old rules with old int engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version", Version: "0.26.0"}},
			},
			falcoVersions: map[string]string{"engine_version_semver": "0.26.0", "engine_version": "26"},
			expectErr:     true,
			testName:      "New Falco with old rules with new semver engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version", Version: "26"}},
			},
			falcoVersions: map[string]string{"engine_version": "26"},
			expectErr:     false,
			testName:      "Old Falco with old rules with old int engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version", Version: "0.26.0"}},
			},
			falcoVersions: map[string]string{"engine_version": "26"},
			expectErr:     true,
			testName:      "Old Falco with old rules with new semver engine version",
		},
	}

	for _, artConf := range testArtifactConfigs {
		t.Run(artConf.testName, func(t *testing.T) {
			config := Config{
				FalcoVersions: artConf.falcoVersions,
			}
			f, err := New("ghcr.io/falcosecurity/rules/my_rule:0.1.0", printer, &config)
			assert.NoError(t, err)

			err = f.checkRequirements(artConf.conf)
			if artConf.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMoveFiles(t *testing.T) {
	type testFile struct {
		path    string
		content string
		replace bool
	}

	tests := []struct {
		name     string
		files    []testFile
		existing []testFile
	}{
		{
			name: "basic file at root",
			files: []testFile{
				{
					path:    "file1.yaml",
					content: "content1",
				},
			},
		},
		{
			name: "file in subdirectory",
			files: []testFile{
				{
					path:    "subdir/file2.yaml",
					content: "content2",
				},
			},
		},
		{
			name: "multiple files in different directories",
			files: []testFile{
				{
					path:    "file1.yaml",
					content: "content1",
				},
				{
					path:    "subdir/file2.yaml",
					content: "content2",
				},
				{
					path:    "subdir/nested/file3.yaml",
					content: "content3",
				},
			},
		},
		{
			name: "existing file with identical content",
			files: []testFile{
				{
					path:    "file1.yaml",
					content: "content1",
					replace: false,
				},
			},
			existing: []testFile{
				{
					path:    "file1.yaml",
					content: "content1",
				},
			},
		},
		{
			name: "existing file with different content",
			files: []testFile{
				{
					path:    "file1.yaml",
					content: "new content",
					replace: true,
				},
			},
			existing: []testFile{
				{
					path:    "file1.yaml",
					content: "old content",
				},
			},
		},
		{
			name: "mix of new and existing files",
			files: []testFile{
				{
					path:    "file1.yaml",
					content: "content1",
					replace: false,
				},
				{
					path:    "subdir/file2.yaml",
					content: "new content2",
					replace: true,
				},
			},
			existing: []testFile{
				{
					path:    "file1.yaml",
					content: "content1",
				},
				{
					path:    "subdir/file2.yaml",
					content: "old content2",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "falcoctl-test-*")
			assert.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			dstDir, err := os.MkdirTemp("", "falcoctl-dst-*")
			assert.NoError(t, err)
			defer os.RemoveAll(dstDir)

			// Setup existing files
			for _, ef := range tt.existing {
				dstPath := filepath.Join(dstDir, ef.path)
				err = os.MkdirAll(filepath.Dir(dstPath), 0o755)
				assert.NoError(t, err)
				err = os.WriteFile(dstPath, []byte(ef.content), 0o644)
				assert.NoError(t, err)
			}

			f, err := New("test-registry/test-ref", output.NewPrinter(pterm.LogLevelDebug, pterm.LogFormatterJSON, os.Stdout), &Config{
				RulesfilesDir: dstDir,
				TmpDir:        tmpDir,
			})
			assert.NoError(t, err)

			var paths []string
			for _, tf := range tt.files {
				fullPath := filepath.Join(f.tmpDir, tf.path)
				err = os.MkdirAll(filepath.Dir(fullPath), 0o755)
				assert.NoError(t, err)
				err = os.WriteFile(fullPath, []byte(tf.content), 0o644)
				assert.NoError(t, err)
				paths = append(paths, fullPath)
			}

			f.currentDigest = "test-digest"
			err = f.moveFiles(paths, dstDir)
			assert.NoError(t, err)

			for _, tf := range tt.files {
				dstPath := filepath.Join(dstDir, tf.path)
				_, err = os.Stat(dstPath)
				assert.NoError(t, err, "file should exist at %s", dstPath)

				content, err := os.ReadFile(dstPath)
				assert.NoError(t, err)
				assert.Equal(t, tf.content, string(content), "file content should match at %s", dstPath)

				// For files marked as replace=false, verify they have identical content with existing files
				if !tf.replace {
					for _, ef := range tt.existing {
						if ef.path == tf.path {
							assert.Equal(t, ef.content, string(content), "file content should not change when replace=false: %s", dstPath)
						}
					}
				}
			}
		})
	}
}
