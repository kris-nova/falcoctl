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

package manifest_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/configuration"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/cmd"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
	testutils "github.com/falcosecurity/falcoctl/pkg/test"
)

var (
	localRegistryHost      string
	localRegistry          *remote.Registry
	testRuleTarball        = "../../../pkg/test/data/rules.tar.gz"
	testPluginTarball      = "../../../pkg/test/data/plugin.tar.gz"
	testPluginPlatform1    = "linux/amd64"
	testPluginPlatform2    = "windows/amd64"
	testPluginPlatform3    = "linux/arm64"
	testPluginPlatform4    = "linux/loong64"
	ctx                    = context.Background()
	pluginMultiPlatformRef string
	rulesRef               string
	output                 = gbytes.NewBuffer()
	rootCmd                *cobra.Command
	opt                    *commonoptions.Common
)

func TestManifest(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Manifest Suite")
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

	// Initialize options for command.
	opt = commonoptions.NewOptions()
	opt.Initialize(commonoptions.WithWriter(output))

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

	// Prepare and push artifact without config layer.
	filePaths := ocipusher.WithFilepaths([]string{testRuleTarball})
	artConfig = oci.ArtifactConfig{}
	Expect(artConfig.ParseDependencies("dep1:1.2.3", "dep2:2.3.1")).ToNot(HaveOccurred())
	options = []ocipusher.Option{
		filePaths,
		ocipusher.WithTags("latest"),
	}

	// Push a rulesfile artifact
	options = append(options, ocipusher.WithArtifactConfig(artConfig))
	rulesRef = localRegistryHost + "/rulesfiles:regular"
	_, err = pusher.Push(ctx, oci.Rulesfile, rulesRef, options...)
	Expect(err).ShouldNot(HaveOccurred())
})

func executeRoot(args []string) error {
	rootCmd.SetArgs(args)
	rootCmd.SetOut(output)
	return cmd.Execute(rootCmd, opt)
}
