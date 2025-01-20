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
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/blang/semver"
	"github.com/pterm/pterm"
	"github.com/robfig/cron/v3"
	"oras.land/oras-go/v2/registry"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/signature"
	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/index/index"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
	ociutils "github.com/falcosecurity/falcoctl/pkg/oci/utils"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

// Follower knows how to track an artifact in a remote repository given the reference.
// It starts a new goroutine to check for updates periodically. If an update is available
// it pulls the new version and installs it in the correct directory.
type Follower struct {
	ref           string
	tag           string
	tmpDir        string
	currentDigest string
	*ocipuller.Puller
	*Config
	logger *pterm.Logger
	config.FalcoVersions
	*output.Printer
}

// Config configuration options for the Follower.
type Config struct {
	WaitGroup *sync.WaitGroup
	// CloseChan used to close the follower.
	CloseChan <-chan bool
	// Resync time after which periodically it checks for new a new version.
	Resync cron.Schedule
	// RulesfilesDir directory where the rulesfile are stored.
	RulesfilesDir string
	// PluginsDir directory where  plugins are stored.
	PluginsDir string
	// AssetsDir directory where assets are stored.
	AssetsDir string
	// ArtifactReference reference to the artifact in a remote repository.
	ArtifactReference string
	// PlainHTTP is set to true if all registry interaction must be in plain http.
	PlainHTTP bool
	// TmpDir directory where to save temporary files.
	TmpDir string
	// FalcoVersions is a struct containing all the required Falco versions that this follower
	// has to take into account when installing artifacts.
	FalcoVersions config.FalcoVersions
	// AllowedTypes specify a list of artifacts that we are allowed to download.
	AllowedTypes oci.ArtifactTypeSlice
	// Signature has the data needed for signature checking
	Signature *index.Signature
}

var isInt = regexp.MustCompile(`^(0|([1-9]\d*))$`)

// New creates a Follower configured with the passed parameters and ready to be used.
// It does not check the correctness of the parameters, make sure everything is initialized.
func New(ref string, printer *output.Printer, conf *Config) (*Follower, error) {
	_, err := utils.GetRegistryFromRef(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to extract registry from ref %q: %w", ref, err)
	}

	parsedRef, err := registry.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to extract tag from ref %q: %w", ref, err)
	}
	tag := parsedRef.Reference

	client, err := ociutils.Client(false)
	if err != nil {
		return nil, err
	}

	puller := ocipuller.NewPuller(client, conf.PlainHTTP, nil)
	if err != nil {
		return nil, err
	}

	// Always create temporary directories at the root level to avoid nesting issues.
	// If TmpDir points to a subdirectory (e.g., /tmp/foo/bar), we use its parent (/tmp/foo)
	// to prevent creating temporary directories inside artifact directories.
	baseDir := conf.TmpDir
	if baseDir != "" {
		baseDir = filepath.Clean(baseDir)
		if filepath.Base(baseDir) != "." {
			baseDir = filepath.Dir(baseDir)
		}
	}

	tmpDir, err := os.MkdirTemp(baseDir, "falcoctl-")
	if err != nil {
		return nil, fmt.Errorf("unable to create temporary directory: %w", err)
	}

	return &Follower{
		ref:           ref,
		tag:           tag,
		tmpDir:        tmpDir,
		Puller:        puller,
		Config:        conf,
		logger:        printer.Logger,
		FalcoVersions: conf.FalcoVersions,
	}, nil
}

// Follow starts a goroutine that periodically checks for updates for the configured artifact.
func (f *Follower) Follow(ctx context.Context) {
	// At start up time of the follower we sync immediately without waiting the resync time.
	f.follow(ctx)

	for {
		now := time.Now()
		next := f.Resync.Next(now)
		select {
		case <-f.CloseChan:
			f.cleanUp()
			f.logger.Info("Follower stopped", f.logger.Args("followerName", f.ref))
			// Notify that the follower is done.
			f.WaitGroup.Done()
			return
		case <-time.After(next.Sub(now)):
			// Start following the artifact.
			f.follow(ctx)
		}
	}
}

func (f *Follower) follow(ctx context.Context) {
	// First thing get the descriptor from remote repo.
	f.logger.Debug("Fetching descriptor from remote repository...", f.logger.Args("followerName", f.ref))
	desc, err := f.Descriptor(ctx, f.ref)
	if err != nil {
		f.logger.Debug(fmt.Sprintf("an error occurred while fetching descriptor from remote repository: %v", err))
		return
	}
	f.logger.Debug("Descriptor correctly fetched", f.logger.Args("followerName", f.ref))

	// If we have already processed then do nothing.
	// TODO(alacuku): check that the file also exists to cover the case when someone has removed the file.
	if desc.Digest.String() == f.currentDigest {
		f.logger.Debug("Nothing to do, artifact already up to date.", f.logger.Args("followerName", f.ref))
		return
	}

	f.logger.Info("Found new artifact version", f.logger.Args("followerName", f.ref, "tag", f.tag))

	// Pull config layer to check falco versions
	artifactConfig, err := f.ArtifactConfig(ctx, f.ref, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		f.logger.Error("Unable to pull config layer", f.logger.Args("followerName", f.ref, "reason", err.Error()))
		return
	}

	err = f.checkRequirements(artifactConfig)
	if err != nil {
		f.logger.Error("Unmet requirements", f.logger.Args("followerName", f.ref, "reason", err.Error()))
		return
	}

	f.logger.Debug("Pulling artifact", f.logger.Args("followerName", f.ref))
	// Pull the artifact from the repository.
	filePaths, res, err := f.pull(ctx)
	if err != nil {
		f.logger.Error("Unable to pull artifact", f.logger.Args("followerName", f.ref, "reason", err.Error()))
		return
	}
	f.logger.Debug("Artifact correctly pulled", f.logger.Args("followerName", f.ref))

	dstDir := f.destinationDir(res)

	// Check if directory exists and is writable.
	err = utils.ExistsAndIsWritable(dstDir)
	if err != nil {
		f.logger.Error("Invalid destination", f.logger.Args("followerName", f.ref, "directory", dstDir, "reason", err.Error()))
		return
	}

	// Move files to their destination
	if err := f.moveFiles(filePaths, dstDir); err != nil {
		return
	}

	f.logger.Info("Artifact correctly installed",
		f.logger.Args("followerName", f.ref, "artifactName", f.ref, "type", res.Type, "digest", res.Digest, "directory", dstDir))
	f.currentDigest = desc.Digest.String()
}

// moveFiles moves files from their temporary location to the destination directory.
// It preserves the directory structure relative to the temporary directory.
// For example, if a file is at "tmpDir/subdir/file.yaml", it will be moved to
// "dstDir/subdir/file.yaml". This ensures that files in subdirectories are moved
// correctly as individual files, not as entire directories.
func (f *Follower) moveFiles(filePaths []string, dstDir string) error {
	// Install the artifacts if necessary.
	for _, path := range filePaths {
		// Get the relative path from the temporary directory to preserve directory structure
		relPath, err := filepath.Rel(f.tmpDir, path)
		if err != nil {
			f.logger.Error("Unable to get relative path", f.logger.Args("followerName", f.ref, "path", path, "reason", err.Error()))
			return err
		}

		dstPath := filepath.Join(dstDir, relPath)
		// Ensure the parent directory exists
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o750); err != nil {
			f.logger.Error("Unable to create destination directory", f.logger.Args(
				"followerName", f.ref,
				"directory", filepath.Dir(dstPath),
				"reason", err.Error(),
			))
			return err
		}

		f.logger.Debug("Installing file", f.logger.Args("followerName", f.ref, "path", relPath))
		// Check if the file exists.
		f.logger.Debug("Checking if file already exists", f.logger.Args("followerName", f.ref, "path", relPath, "directory", dstDir))
		exists, err := utils.FileExists(dstPath)
		if err != nil {
			f.logger.Error("Unable to check existence for file", f.logger.Args("followerName", f.ref, "path", relPath, "reason", err.Error()))
			return err
		}

		if !exists {
			f.logger.Debug("Moving file", f.logger.Args("followerName", f.ref, "path", relPath, "destDirectory", dstDir))
			if err = utils.Move(path, dstPath); err != nil {
				f.logger.Error("Unable to move file", f.logger.Args("followerName", f.ref, "path", relPath, "destDirectory", dstDir, "reason", err.Error()))
				return err
			}
			f.logger.Debug("File correctly installed", f.logger.Args("followerName", f.ref, "path", path))
			// It's done, move to the next file.
			continue
		}

		f.logger.Debug(fmt.Sprintf("file %q already exists in %q, checking if it is equal to the existing one", relPath, dstDir),
			f.logger.Args("followerName", f.ref))

		// Check if the files are equal.
		eq, err := equal([]string{path, dstPath})
		if err != nil {
			f.logger.Error("Unable to compare files", f.logger.Args("followerName", f.ref, "existingFile", dstPath, "reason", err.Error()))
			return err
		}

		if !eq {
			f.logger.Debug(fmt.Sprintf("Overwriting file %q with file %q", dstPath, path), f.logger.Args("followerName", f.ref))
			if err = utils.Move(path, dstPath); err != nil {
				f.logger.Error("Unable to overwrite file", f.logger.Args("followerName", f.ref, "existingFile", dstPath, "reason", err.Error()))
				return err
			}
		} else {
			f.logger.Debug("The two file are equal, nothing to be done")
		}
	}
	return nil
}

// pull downloads, extracts, and installs the artifact.
func (f *Follower) pull(ctx context.Context) (filePaths []string, res *oci.RegistryResult, err error) {
	f.logger.Debug("Check if pulling an allowed type of artifact", f.logger.Args("followerName", f.ref))
	if err := f.Puller.CheckAllowedType(ctx, f.ref, runtime.GOOS, runtime.GOARCH, f.Config.AllowedTypes.Types); err != nil {
		return nil, nil, err
	}

	// Pull the artifact from the repository.
	f.logger.Debug("Pulling artifact %q", f.logger.Args("followerName", f.ref, "artifactName", f.ref))
	res, err = f.Pull(ctx, f.ref, f.tmpDir, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return filePaths, res, fmt.Errorf("unable to pull artifact %q: %w", f.ref, err)
	}

	repo, err := utils.RepositoryFromRef(f.ref)
	if err != nil {
		return filePaths, res, err
	}

	digestRef := fmt.Sprintf("%s@%s", repo, res.RootDigest)

	// Verify the signature if needed
	if f.Config.Signature != nil {
		f.logger.Debug("Verifying signature", f.logger.Args("followerName", f.ref, "digest", digestRef))
		err = signature.Verify(ctx, digestRef, f.Config.Signature)
		if err != nil {
			return filePaths, res, fmt.Errorf("could not verify signature for %s: %w", res.RootDigest, err)
		}
		f.logger.Debug("Signature successfully verified")
	}

	f.logger.Debug("Extracting artifact", f.logger.Args("followerName", f.ref))
	res.Filename = filepath.Join(f.tmpDir, res.Filename)

	file, err := os.Open(res.Filename)
	if err != nil {
		return filePaths, res, fmt.Errorf("unable to open file %q: %w", res.Filename, err)
	}

	// Extract artifact and move it to its destination directory
	filePaths, err = utils.ExtractTarGz(ctx, file, f.tmpDir, 0)
	if err != nil {
		return filePaths, res, fmt.Errorf("unable to extract %q to %q: %w", res.Filename, f.tmpDir, err)
	}

	f.logger.Debug("Cleaning up leftovers files", f.logger.Args("followerName", f.ref))
	err = os.Remove(res.Filename)
	if err != nil {
		return filePaths, res, fmt.Errorf("unable to remove file %q: %w", res.Filename, err)
	}

	return filePaths, res, err
}

// destinationDir returns the dir where to save the artifact.
func (f *Follower) destinationDir(res *oci.RegistryResult) string {
	var dir string
	switch res.Type {
	case oci.Plugin:
		dir = f.PluginsDir
	case oci.Rulesfile:
		dir = f.RulesfilesDir
	case oci.Asset:
		dir = f.AssetsDir
	}
	return dir
}

func (f *Follower) checkRequirements(artifactConfig *oci.ArtifactConfig) error {
	// Check if each requirement specified in a config layer meet the needs of the
	// currently running Falco.

	for _, requirement := range artifactConfig.Requirements {
		reqName := requirement.Name
		falcoVer, ok := f.FalcoVersions[requirement.Name]
		if !ok {
			return fmt.Errorf("unrecognized key %s: Falco does not satisfy this requirement", reqName)
		}
		if isInt.MatchString(requirement.Version) { // handle integers
			falcoVerInt, err := strconv.Atoi(falcoVer)
			if err != nil {
				return fmt.Errorf("expected integer for key %s: %w", reqName, err)
			}

			reqVerInt, err := strconv.Atoi(requirement.Version)
			if err != nil {
				return fmt.Errorf("expected integer for key %s: %w", reqName, err)
			}

			if falcoVerInt < reqVerInt {
				return fmt.Errorf("incompatible versions, Falco: %d, Requirement: %s:%d", falcoVerInt, reqName, reqVerInt)
			}
		} else { // handle semver
			falcoSemver, err := semver.Parse(falcoVer)
			if err != nil {
				return fmt.Errorf("expected semver for key %s: %w", reqName, err)
			}

			reqSemver, err := semver.Parse(requirement.Version)
			if err != nil {
				return fmt.Errorf("expected semver for key %s: %w", reqName, err)
			}

			// Normal semver check
			if falcoSemver.Major != reqSemver.Major {
				return fmt.Errorf("incompatible versions, MAJOR mismatch, Falco: %s, Requirement: %s:%s", falcoSemver.String(), reqName, reqSemver.String())
			} else if falcoSemver.Compare(reqSemver) < 0 {
				return fmt.Errorf("incompatible versions, MINOR mismatch, Falco: %s, Requirement: %s:%s", falcoSemver.String(), reqName, reqSemver.String())
			}
		}
	}

	return nil
}

func (f *Follower) cleanUp() {
	if err := os.RemoveAll(f.tmpDir); err != nil {
		f.logger.Warn("Unable to clean working directory", f.logger.Args("followerName", f.ref, "directory", f.tmpDir, "reason", err))
	}
}

// equal checks if the two files are equal by comparing their sha256 hashes.
func equal(files []string) (bool, error) {
	var hashes []string
	if len(files) != 2 {
		return false, fmt.Errorf("expecting 2 files but got %d", len(files))
	}

	hasher := sha256.New()

	for _, file := range files {
		filePath := filepath.Clean(file)
		f, err := os.Open(filePath)
		if err != nil {
			return false, err
		}

		if _, err := io.Copy(hasher, f); err != nil {
			return false, err
		}
		hashes = append(hashes, string(hasher.Sum([]byte{})))

		// Clean up.
		if err := f.Close(); err != nil {
			return false, fmt.Errorf("unable to close file %q: %w", filePath, err)
		}

		hasher.Reset()
	}

	if hashes[0] != hashes[1] {
		return false, nil
	}

	return true, nil
}
