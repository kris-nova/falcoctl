// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 The Falco Authors
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

package pusher_test

import (
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	"github.com/falcosecurity/falcoctl/pkg/output"
	"github.com/falcosecurity/falcoctl/pkg/test"
)

var _ = Describe("Pusher", func() {
	var (
		pusher                *ocipusher.Pusher
		tracker               output.Tracker
		ref                   string
		filePathsAndPlatforms ocipusher.Option
		filePaths             ocipusher.Option
		tags                  ocipusher.Option
		config                ocipusher.Option
		annotationSource      ocipusher.Option
		options               []ocipusher.Option
		repoAndTag            = "/generic-repo:tag"
		repo                  registry.Repository
		result                *oci.RegistryResult
		artifactType          oci.ArtifactType
		listTags              []string
		fetchedTags           []string
		sourceKey             = v1.AnnotationSource
		sourceValue           string
		plainHTTP             = true
		err                   error
	)
	JustBeforeEach(func() {
		pusher = ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
		ref = localRegistryHost + repoAndTag
		result, err = pusher.Push(ctx, artifactType, ref, options...)
	})

	JustAfterEach(func() {
		plainHTTP = true
		repoAndTag = "/generic-repo:tag"
	})

	Context("handling plugin artifacts", func() {
		BeforeEach(func() {
			artifactType = oci.Plugin
		})
		Context("without platform", func() {
			BeforeEach(func() {
				filePathsAndPlatforms = ocipusher.WithFilepaths([]string{testPluginTarball})
				options = []ocipusher.Option{filePathsAndPlatforms}
			})
			It("should error", func() {
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, ocipusher.ErrInvalidPlatformFormat)).To(BeTrue())
				Expect(result).To(BeNil())
			})
		})

		Context("with config", func() {
			BeforeEach(func() {
				filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{testPluginTarball}, []string{testPluginPlatform1})
				artConfig := oci.ArtifactConfig{}
				Expect(artConfig.ParseDependencies("my-dep:1.2.3|my-alt-dep:1.4.5")).ToNot(HaveOccurred())
				Expect(artConfig.ParseRequirements("my-req:7.8.9")).ToNot(HaveOccurred())
				config = ocipusher.WithArtifactConfig(artConfig)
				options = []ocipusher.Option{filePathsAndPlatforms, config}
			})
			It("should succeed", func() {
				Expect(err).ToNot(HaveOccurred())
				Expect(result).ToNot(BeNil())
			})
		})

		Context("with filepaths and platform", func() {
			When("mismatch between filepath and platform numbers", func() {
				BeforeEach(func() {
					filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{testPluginTarball}, []string{testPluginPlatform1, "mismatch"})
					options = append(options, filePathsAndPlatforms)
				})
				It("should error", func() {
					Expect(err).To(HaveOccurred())
					Expect(errors.Is(err, ocipusher.ErrMismatchFilepathAndPlatform)).To(BeTrue())
					Expect(result).To(BeNil())
				})
			})

			When("correct number of filepaths and platforms", func() {
				Context("pushing only one plugin: 1 filepath, 1 platform with multiple tags and with annotation source", func() {
					BeforeEach(func() {
						// Additional tags to be added to the artifact.
						listTags = []string{"tag1", "tag2", "tag3"}
						tags = ocipusher.WithTags(listTags...)
						// One version of the artifact for a single platform.
						filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{testPluginTarball}, []string{testPluginPlatform1})
						// Adding annotation source to the index.
						sourceValue = "https://plugins/source/test"
						annotationSource = ocipusher.WithAnnotationSource(sourceValue)
						options = []ocipusher.Option{tags, filePathsAndPlatforms, annotationSource}

						// Repo and default tag for the artifact
						repoAndTag = "/plugin-test:latest"
						repo, err = localRegistry.Repository(ctx, "plugin-test")
						Expect(err).To(BeNil())
					})

					It("should succeed", func() {
						Expect(err).ToNot(HaveOccurred())
						Expect(result).ToNot(BeNil())
						d, reader, err := repo.FetchReference(ctx, ref)
						Expect(err).ToNot(HaveOccurred())
						index, err := test.ImageIndexFromReader(reader)
						Expect(err).ToNot(HaveOccurred())
						// Being the artifact of type plugin we expect that the retrieved descriptor is of type image index.
						Expect(d.MediaType).To(Equal(v1.MediaTypeImageIndex))
						Expect(d.Digest.String()).To(Equal(result.RootDigest))
						Expect(index.Manifests).To(HaveLen(1))
						Expect(fmt.Sprintf("%s/%s", index.Manifests[0].Platform.OS, index.Manifests[0].Platform.Architecture)).To(Equal(testPluginPlatform1))
						// Check layer and config media types.
						reader, err = repo.Fetch(ctx, index.Manifests[0])
						Expect(err).ToNot(HaveOccurred())
						manifest, err := test.ManifestFromReader(reader)
						Expect(err).ToNot(HaveOccurred())
						Expect(manifest.Config.MediaType).To(Equal(oci.FalcoPluginConfigMediaType))
						Expect(manifest.Layers).To(HaveLen(1))
						Expect(manifest.Layers[0].MediaType).To(Equal(oci.FalcoPluginLayerMediaType))

						// Check that annotation source is present and contains right value.
						Expect(index.Annotations).To(HaveKeyWithValue(sourceKey, sourceValue))

						// Check that the tags have also been pushed.
						err = repo.Tags(ctx, "", func(tags []string) error {
							fetchedTags = nil
							fetchedTags = append(fetchedTags, tags...)
							return nil
						})
						Expect(err).ToNot(HaveOccurred())
						// It must have the initial tag + the other three tags.
						Expect(fetchedTags).To(HaveLen(4))
						Expect(fetchedTags).To(ContainElements(listTags[0], listTags[1], listTags[2]))
					})
				})

				Context("pushing multiple flavors of plugin: 3 filepath, 3 platform without tag", func() {
					BeforeEach(func() {
						// Different files, one for each platform.
						filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{testPluginTarball, testPluginTarball, testPluginTarball, testPluginTarball},
							[]string{testPluginPlatform1, testPluginPlatform2, testPluginPlatform3, testPluginPlatform4})
						options = []ocipusher.Option{filePathsAndPlatforms}
						// Pushing the artifact without an explicit tag, the default tag (latest) will be added by the pusher.
						repoAndTag = "/plugin-test-three-flavors"
						repo, err = localRegistry.Repository(ctx, "plugin-test-three-flavors")
						Expect(err).To(BeNil())
					})

					It("should succeed", func() {
						Expect(err).ToNot(HaveOccurred())
						Expect(result).ToNot(BeNil())
						// Since we have not specified a tag for the artifact we expect that the pusher will add it.
						d, reader, err := repo.FetchReference(ctx, ref+":latest")
						Expect(err).ToNot(HaveOccurred())
						index, err := test.ImageIndexFromReader(reader)
						Expect(err).ToNot(HaveOccurred())
						// Being the artifact of type plugin we expect that the retrieved descriptor is of type image index.
						Expect(d.MediaType).To(Equal(v1.MediaTypeImageIndex))
						Expect(d.Digest.String()).To(Equal(result.RootDigest))
						Expect(index.Manifests).To(HaveLen(4))
						Expect(fmt.Sprintf("%s/%s", index.Manifests[0].Platform.OS, index.Manifests[0].Platform.Architecture)).To(Equal(testPluginPlatform1))
						Expect(fmt.Sprintf("%s/%s", index.Manifests[1].Platform.OS, index.Manifests[1].Platform.Architecture)).To(Equal(testPluginPlatform2))
						Expect(fmt.Sprintf("%s/%s", index.Manifests[2].Platform.OS, index.Manifests[2].Platform.Architecture)).To(Equal(testPluginPlatform3))
						Expect(fmt.Sprintf("%s/%s", index.Manifests[3].Platform.OS, index.Manifests[3].Platform.Architecture)).To(Equal(testPluginPlatform4))
					})
				})

			})

		})
	})

	Context("handling rulesfile artifacts", func() {
		BeforeEach(func() {
			artifactType = oci.Rulesfile
		})

		Context("with filepaths", func() {
			When("only one rulesfile is given", func() {
				BeforeEach(func() {
					filePaths = ocipusher.WithFilepaths([]string{testRuleTarball})
					options = []ocipusher.Option{filePaths}
					// Repo and default tag for the artifact
					repoAndTag = "/rulesfile-test:1.2.3"
					repo, err = localRegistry.Repository(ctx, "rulesfile-test")
					Expect(err).To(BeNil())
				})
				It("should succeed", func() {
					Expect(err).ToNot(HaveOccurred())
					Expect(result).ToNot(BeNil())
					d, reader, err := repo.FetchReference(ctx, ref)
					Expect(err).ToNot(HaveOccurred())
					manifest, err := test.ManifestFromReader(reader)
					Expect(err).ToNot(HaveOccurred())
					// Being the artifact of type rulesfile we expect that the retrieved descriptor is of type manifest.
					Expect(d.MediaType).To(Equal(v1.MediaTypeImageManifest))
					Expect(d.Digest.String()).To(Equal(result.RootDigest))
					// It must have only one layer since no config layer is configured.
					Expect(manifest.Layers).To(HaveLen(1))
					// It must have the rulesfile's layer mediatype.
					Expect(manifest.Layers[0].MediaType).To(Equal(oci.FalcoRulesfileLayerMediaType))
					// It must have the rulesfile's config mediatype.
					Expect(manifest.Config.MediaType).To(Equal(oci.FalcoRulesfileConfigMediaType))
				})
			})

			When("multiple rulesfile are given", func() {
				BeforeEach(func() {
					filePaths = ocipusher.WithFilepaths([]string{testRuleTarball, testRuleTarball})
					options = []ocipusher.Option{filePaths}
					// Repo and default tag for the artifact
					repoAndTag = "/rulesfile-test:1.2.4"
					repo, err = localRegistry.Repository(ctx, "rulesfile-test")
					Expect(err).To(BeNil())
				})
				It("should error", func() {
					Expect(err).To(HaveOccurred())
					Expect(errors.Is(err, ocipusher.ErrInvalidNumberRulesfiles)).To(BeTrue())
					Expect(result).To(BeNil())
				})
			})
		})

		Context("with dependencies", func() {
			When("valid dependencies and default tag", func() {
				BeforeEach(func() {
					filePaths = ocipusher.WithFilepaths([]string{testRuleTarball})
					artConfig := oci.ArtifactConfig{}
					Expect(artConfig.ParseDependencies("dep1:1.2.3", "dep2:2.3.1")).ToNot(HaveOccurred())
					options = []ocipusher.Option{
						filePaths,
						ocipusher.WithArtifactConfig(artConfig),
					}
					// Repo and default tag for the artifact
					repoAndTag = "/rulesfile-dependencies"
					repo, err = localRegistry.Repository(ctx, "rulesfile-dependencies")
					Expect(err).To(BeNil())
				})
				It("should succeed", func() {
					Expect(err).ToNot(HaveOccurred())
					Expect(result).ToNot(BeNil())
					d, reader, err := repo.FetchReference(ctx, ref+":latest")
					Expect(err).ToNot(HaveOccurred())
					manifest, err := test.ManifestFromReader(reader)
					Expect(err).ToNot(HaveOccurred())
					// Being the artifact of type rulesfile we expect that the retrieved descriptor is of type manifest.
					Expect(d.MediaType).To(Equal(v1.MediaTypeImageManifest))
					Expect(d.Digest.String()).To(Equal(result.RootDigest))
					// It must have only one layer since no config layer is configured.
					Expect(manifest.Layers).To(HaveLen(1))
					// It must have the rulesfile's layer mediatype.
					Expect(manifest.Layers[0].MediaType).To(Equal(oci.FalcoRulesfileLayerMediaType))
					// It must have the rulesfile's config mediatype.
					Expect(manifest.Config.MediaType).To(Equal(oci.FalcoRulesfileConfigMediaType))
					// Fetch the config layer
					reader, err = repo.Fetch(ctx, manifest.Config)
					Expect(err).ToNot(HaveOccurred())
					dep, err := test.DependenciesFromReader(reader)
					Expect(err).ToNot(HaveOccurred())
					Expect(dep).ToNot(BeNil())
					// Check that we have the same number of deps that we set before.
					Expect(len(dep.Dependencies)).To(Equal(2))
				})
			})
		})

		Context("with multiple tags", func() {
			BeforeEach(func() {
				// Additional tags to be added to the artifact.
				listTags = []string{"tag1", "tag2", "tag3"}
				tags = ocipusher.WithTags(listTags...)
				filePaths = ocipusher.WithFilepaths([]string{testRuleTarball})
				options = []ocipusher.Option{filePaths, tags}
				// Repo and default tag for the artifact
				repoAndTag = "/rulesfile-multiple-tags:latest"
				repo, err = localRegistry.Repository(ctx, "rulesfile-multiple-tags")
				Expect(err).To(BeNil())
			})

			It("should succeed", func() {
				Expect(err).ToNot(HaveOccurred())
				Expect(result).ToNot(BeNil())
				err = repo.Tags(ctx, "", func(tags []string) error {
					fetchedTags = nil
					fetchedTags = append(fetchedTags, tags...)
					return nil
				})
				Expect(err).ToNot(HaveOccurred())
				// It must have the initial tag + the other three tags.
				Expect(fetchedTags).To(HaveLen(4))
				Expect(fetchedTags).To(ContainElements(listTags[0], listTags[1], listTags[2]))
			})
		})
	})

	Context("handling asset artifacts", func() {
		BeforeEach(func() {
			artifactType = oci.Asset
		})

		When("only one asset tarball is given", func() {
			BeforeEach(func() {
				filePaths = ocipusher.WithFilepaths([]string{testRuleTarball}) // not interested in the content
				options = []ocipusher.Option{filePaths}
				// Repo and default tag for the artifact
				repoAndTag = "/one-asset-test:1.2.3"
				repo, err = localRegistry.Repository(ctx, "one-asset-test")
				Expect(err).To(BeNil())
			})
			It("should succeed", func() {
				Expect(err).ToNot(HaveOccurred())
				Expect(result).ToNot(BeNil())
				d, reader, err := repo.FetchReference(ctx, ref)
				Expect(err).ToNot(HaveOccurred())
				manifest, err := test.ManifestFromReader(reader)
				Expect(err).ToNot(HaveOccurred())
				// Being the artifact of type asset we expect that the retrieved descriptor is of type manifest.
				Expect(d.MediaType).To(Equal(v1.MediaTypeImageManifest))
				// Checking the digest is correct.
				Expect(d.Digest.String()).To(Equal(result.RootDigest))
				// It must have only one layer since no config layer is configured.
				Expect(manifest.Layers).To(HaveLen(1))
				// The layer has to be of type asset.
				Expect(manifest.Layers[0].MediaType).To(Equal(oci.FalcoAssetLayerMediaType))
				// It must have the asset config layer media type.
				Expect(manifest.Config.MediaType).To(Equal(oci.FalcoAssetConfigMediaType))
			})
		})

		When("multiple assets tarballs are given", func() {
			BeforeEach(func() {
				filePaths = ocipusher.WithFilepaths([]string{testRuleTarball, testRuleTarball}) // not interested in the content
				options = []ocipusher.Option{filePaths}
				// Repo and default tag for the artifact
				repoAndTag = "/multiple-assets-test:1.2.3"
				repo, err = localRegistry.Repository(ctx, "multiple-assets-test")
				Expect(err).To(BeNil())
			})
			It("should error", func() {
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, ocipusher.ErrInvalidNumberAssets)).To(BeTrue())
				Expect(result).To(BeNil())
			})
		})
	})

	Context("generic error handling", func() {
		When("file does not exist", func() {
			BeforeEach(func() {
				filePaths = ocipusher.WithFilepaths([]string{"../not/existing.file"})
				options = []ocipusher.Option{filePaths}
			})
			It("should error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("unable to store artifact"))
				Expect(result).To(BeNil())
			})
		})

		When("invalid artifact reference", func() {
			BeforeEach(func() {
				filePaths = ocipusher.WithFilepaths([]string{testRuleTarball})
				options = []ocipusher.Option{filePaths}
				// Repo and default tag for the artifact
				repoAndTag = "/Invalid:Ref:Artifact"
			})
			It("should error", func() {
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, errdef.ErrInvalidReference)).To(BeTrue())
				Expect(result).To(BeNil())
			})
		})

		When("generic error on remote repo operation", func() {
			BeforeEach(func() {
				filePaths = ocipusher.WithFilepaths([]string{testRuleTarball})
				options = []ocipusher.Option{filePaths}
				// This will cause operations on remote repo to fail.
				plainHTTP = false
			})
			It("should error", func() {
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})
		})
	})
})
