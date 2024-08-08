// Copyright 2020-2024 Buf Technologies, Inc.
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

package internal

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/bufbuild/buf/private/buf/bufcli"
	"github.com/bufbuild/buf/private/bufpkg/bufconfig"
)

// GetModuleConfigForProtocPlugin gets ModuleConfigs for the protoc plugin implementations.
//
// This is the same in both plugins so we just pulled it out to a common spot.
func GetModuleConfigForProtocPlugin(
	ctx context.Context,
	configOverride string,
	module string,
) (bufconfig.ModuleConfig, error) {
	bufYAMLFile, err := bufcli.GetBufYAMLFileForDirPathOrOverride(
		ctx,
		".",
		configOverride,
	)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return bufconfig.DefaultModuleConfigV1, nil
		}
		return nil, err
	}
	if module == "" {
		module = "."
	}
	moduleConfigsMatchingDirPath := []bufconfig.ModuleConfig{}
	for _, moduleConfig := range bufYAMLFile.ModuleConfigs() {
		// If we have a v1beta1 or v1 buf.yaml, dirPath will be ".". Using the ModuleConfig from
		// a v1beta1 or v1 buf.yaml file matches the pre-refactor behavior.
		//
		// If we have a v2 buf.yaml, users have to provide a module path or full name, otherwise
		// we can't deduce what ModuleConfig to use.
		if fullName := moduleConfig.ModuleFullName(); fullName != nil && fullName.String() == module {
			return moduleConfig, nil
		}
		if dirPath := moduleConfig.DirPath(); dirPath == module {
			moduleConfigsMatchingDirPath = append(moduleConfigsMatchingDirPath, moduleConfig)
		}
	}
	switch len(moduleConfigsMatchingDirPath) {
	case 0:
		// TODO: this error messsage seems easy to update.
		// TODO: point to a webpage that explains this.
		return nil, errors.New(`could not determine which module to pull configuration from. See the docs for more details`)
	case 1:
		return moduleConfigsMatchingDirPath[0], nil
	default:
		return nil, fmt.Errorf("multiple modules found at %q, specify its full name as <remote/owner/module> instead", module)
	}
}
