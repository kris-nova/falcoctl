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

package driverdistro

import (
	"testing"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"
)

func TestDistroFlatcarInitFixup(t *testing.T) {
	type config struct {
		VersionID string `ini:"VERSION_ID"`
	}

	type testCase struct {
		cfg         interface{}
		krExpected  string
		errExpected bool
	}
	testCases := []testCase{
		{
			cfg:        &config{VersionID: "3185.0.0"},
			krExpected: "3185.0.0",
		},
		{
			cfg:         &struct{}{},
			errExpected: true,
		},
	}

	for _, tCase := range testCases {
		fl := &flatcar{generic: &generic{}}
		cfg := ini.Empty()
		err := cfg.ReflectFrom(tCase.cfg)
		require.NoError(t, err)

		kr := kernelrelease.KernelRelease{}
		err = fl.init(kr, "", cfg)
		if tCase.errExpected {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			fixedKr := fl.FixupKernel(kr)
			assert.Equal(t, tCase.krExpected, fixedKr.String())
		}
	}
}
