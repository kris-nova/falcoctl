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
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/configuration"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"oras.land/oras-go/v2/registry/remote"

	testutils "github.com/falcosecurity/falcoctl/pkg/test"
)

var (
	localRegistryHost   string
	localRegistry       *remote.Registry
	testRuleTarball     = "../../test/data/rules.tar.gz"
	testPluginTarball   = "../../test/data/plugin.tar.gz"
	testPluginPlatform1 = "linux/amd64"
	testPluginPlatform2 = "windows/amd64"
	testPluginPlatform3 = "linux/arm64"
	testPluginPlatform4 = "linux/loong64"
	ctx                 = context.Background()
)

func TestPusher(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Pusher Suite")
}

var _ = BeforeSuite(func() {
	var err error
	config := &configuration.Configuration{}
	port, err := testutils.FreePort()
	Expect(err).ToNot(HaveOccurred())
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
})
