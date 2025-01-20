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

package puller_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/configuration"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	"github.com/falcosecurity/falcoctl/pkg/oci/repository"
	testutils "github.com/falcosecurity/falcoctl/pkg/test"
)

var (
	localRegistryHost         string
	localRegistry             *remote.Registry
	testRuleTarball           = "../../test/data/rules.tar.gz"
	testPluginTarball         = "../../test/data/plugin.tar.gz"
	testPluginPlatform1       = "linux/amd64"
	testPluginPlatform2       = "windows/amd64"
	testPluginPlatform3       = "linux/arm64"
	testPluginPlatform4       = "linux/loong64"
	ctx                       = context.Background()
	destinationDir            string
	pluginMultiPlatformRef    string
	rulesRef                  string
	artifactWithuoutConfigRef string
)

func TestPuller(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Puller Suite")
}

var _ = BeforeSuite(func() {
	var err error
	config := &configuration.Configuration{}
	// Get a free port to be used by the registry.
	port, err := testutils.FreePort()
	Expect(err).ToNot(HaveOccurred())
	// Create the registry address to which will bind.
	config.HTTP.Addr = fmt.Sprintf("localhost:%d", port)
	localRegistryHost = config.HTTP.Addr

	// Create the oras registry.
	localRegistry, err = testutils.NewOrasRegistry(localRegistryHost, true)
	Expect(err).ToNot(HaveOccurred())

	// Start the local registry.
	go func() {
		err := testutils.StartRegistry(context.Background(), config)
		Expect(err).ToNot(BeNil())
	}()

	// Check that the registry is up and accepting connections.
	Eventually(func(g Gomega) error {
		res, err := http.Get(fmt.Sprintf("http://%s", config.HTTP.Addr))
		g.Expect(err).ShouldNot(HaveOccurred())
		g.Expect(res.StatusCode).Should(Equal(http.StatusOK))
		return err
	}).WithTimeout(time.Second * 5).ShouldNot(HaveOccurred())

	// Create the temporary dir where artifacts are saved.
	destinationDir, err = os.MkdirTemp("", "falcoctl-puller-tests-")
	Expect(err).ShouldNot(HaveOccurred())

	// Push the artifacts to the registry.
	// Same artifacts will be used to test the puller code.
	pusher := ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), true, nil)

	// Push plugin artifact with multiple architectures.
	filePathsAndPlatforms := ocipusher.WithFilepathsAndPlatforms([]string{testPluginTarball, testPluginTarball, testPluginTarball, testPluginTarball},
		[]string{testPluginPlatform1, testPluginPlatform2, testPluginPlatform3, testPluginPlatform4})
	pluginMultiPlatformRef = localRegistryHost + "/plugins:multiplatform"
	artConfig := oci.ArtifactConfig{}
	Expect(artConfig.ParseDependencies("my-dep:1.2.3|my-alt-dep:1.4.5")).ToNot(HaveOccurred())
	Expect(artConfig.ParseRequirements("my-req:7.8.9")).ToNot(HaveOccurred())
	artifactConfig := ocipusher.WithArtifactConfig(artConfig)

	// Build options slice.
	options := []ocipusher.Option{filePathsAndPlatforms, artifactConfig}

	// Push the plugin artifact.
	_, err = pusher.Push(ctx, oci.Plugin, pluginMultiPlatformRef, options...)
	Expect(err).ShouldNot(HaveOccurred())

	// Prepare and push rulesfile artifact.
	filePaths := ocipusher.WithFilepaths([]string{testRuleTarball})
	artConfig = oci.ArtifactConfig{}
	Expect(artConfig.ParseDependencies("dep1:1.2.3", "dep2:2.3.1")).ToNot(HaveOccurred())
	options = []ocipusher.Option{
		filePaths,
		ocipusher.WithTags("latest"),
		ocipusher.WithArtifactConfig(artConfig),
	}
	// Push a new artifact
	rulesRef = localRegistryHost + "/rulesfiles:regular"
	_, err = pusher.Push(ctx, oci.Rulesfile, rulesRef, options...)
	Expect(err).ShouldNot(HaveOccurred())

	// Push artifact without config layer.
	artifactWithuoutConfigRef = localRegistryHost + "/artifact:noconfig"
	err = pushArtifactWithoutConfigLayer(ctx, artifactWithuoutConfigRef, testRuleTarball, authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)))
	Expect(err).ShouldNot(HaveOccurred())
})

func pushArtifactWithoutConfigLayer(ctx context.Context, ref, artifactPath string, client remote.Client) error {
	repo, err := repository.NewRepository(ref,
		repository.WithClient(client),
		repository.WithPlainHTTP(true))
	if err != nil {
		return err
	}

	fileStore, err := file.New(destinationDir)
	if err != nil {
		return err
	}

	// Get absolute path of the artifact.

	path, err := filepath.Abs(artifactPath)
	if err != nil {
		return err
	}

	desc, err := fileStore.Add(ctx, filepath.Base(artifactPath), oci.FalcoRulesfileLayerMediaType, path)
	if err != nil {
		return err
	}

	packOptions := oras.PackOptions{
		PackImageManifest: true,
	}

	desc, err = oras.Pack(ctx, fileStore, "", []v1.Descriptor{desc}, packOptions)

	if err != nil {
		return err
	}

	if err := oras.CopyGraph(ctx, fileStore, repo, desc, oras.DefaultCopyGraphOptions); err != nil {
		return err
	}

	rootReader, err := fileStore.Fetch(ctx, desc)
	if err != nil {
		return err
	}
	defer rootReader.Close()

	// Tag the root descriptor remotely.
	err = repo.PushReference(ctx, desc, rootReader, repo.Reference.Reference)
	if err != nil {
		return err
	}

	return nil
}

var _ = AfterSuite(func() {
	Expect(os.RemoveAll(destinationDir)).Should(Succeed())
})
