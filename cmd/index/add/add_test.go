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

package add_test

import (
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"

	"github.com/falcosecurity/falcoctl/cmd"
)

//nolint:lll // no need to check for line length.
var indexAddUsage = `Usage:
falcoctl index add [NAME] [URL] [BACKEND] [TOKEN] [flags]

Flags:
-h, --help   help for add

Global Flags:
      --config string       config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --log-format string   Set formatting for logs (color, text, json) (default "color")
      --log-level string    Set level for logs (info, warn, debug, trace) (default "info")
`

//nolint:lll // no need to check for line length.
var indexAddHelp = `Add an index to the local falcoctl configuration. Indexes are used to perform search operations for artifacts

Usage:
  falcoctl index add [NAME] [URL] [BACKEND] [TOKEN] [flags]

Flags:
  -h, --help   help for add

Global Flags:
      --config string       config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --log-format string   Set formatting for logs (color, text, json) (default "color")
      --log-level string    Set level for logs (info, warn, debug, trace) (default "info")
`

var addAssertFailedBehavior = func(usage, specificError string) {
	It("check that fails and the usage is not printed", func() {
		Expect(err).To(HaveOccurred())
		Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(usage)))
		Expect(output).Should(gbytes.Say(regexp.QuoteMeta(specificError)))
	})
}

var indexAddTests = Describe("add", func() {

	var (
		indexCmd  = "index"
		addCmd    = "add"
		indexName = "testName"
	)

	// Each test gets its own root command and runs it.
	// The err variable is asserted by each test.
	JustBeforeEach(func() {
		rootCmd = cmd.New(ctx, opt)
		err = executeRoot(args)
	})

	JustAfterEach(func() {
		Expect(output.Clear()).ShouldNot(HaveOccurred())
	})

	Context("help message", func() {
		BeforeEach(func() {
			args = []string{indexCmd, addCmd, "--help"}
		})

		It("should match the saved one", func() {

			Expect(output).Should(gbytes.Say(regexp.QuoteMeta(indexAddHelp)))
		})
	})

	// Here we are testing failure cases for adding a new index.
	Context("failure", func() {
		When("without URL", func() {
			BeforeEach(func() {
				args = []string{indexCmd, addCmd, "--config", configFile, indexName}
			})
			addAssertFailedBehavior(indexAddUsage, "ERROR accepts between 2 and 4 arg(s), received 1")
		})

		When("with invalid URL", func() {
			BeforeEach(func() {
				args = []string{indexCmd, addCmd, "--config", configFile, indexName, "NOTAPROTOCAL://something"}
			})
			addAssertFailedBehavior(indexAddUsage, "ERROR unable to add index: unable to fetch index \"testName\""+
				" with URL \"NOTAPROTOCAL://something\": unable to fetch index: cannot fetch index: Get "+
				"\"notaprotocal://something\": unsupported protocol scheme \"notaprotocal\"")
		})

		When("with invalid backend", func() {
			BeforeEach(func() {
				args = []string{indexCmd, addCmd, "--config", configFile, indexName, "http://noindex", "notabackend"}
			})
			addAssertFailedBehavior(indexAddUsage, "ERROR unable to add index: unable to fetch index \"testName\" "+
				"with URL \"http://noindex\": unsupported index backend type: notabackend")
		})
	})

})
