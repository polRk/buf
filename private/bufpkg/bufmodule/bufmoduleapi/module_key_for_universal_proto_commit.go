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

package bufmoduleapi

import (
	"context"
	"fmt"

	"github.com/bufbuild/buf/private/bufpkg/bufmodule"
	"github.com/gofrs/uuid/v5"
)

func getModuleKeyForUniversalProtoCommit(
	ctx context.Context,
	v1ProtoModuleProvider *v1ProtoModuleProvider,
	v1ProtoOwnerProvider *v1ProtoOwnerProvider,
	registry string,
	universalProtoCommit *universalProtoCommit,
) (bufmodule.ModuleKey, error) {
	moduleFullName, err := getModuleFullNameForRegistryProtoOwnerIdProtoModuleId(
		ctx,
		v1ProtoModuleProvider,
		v1ProtoOwnerProvider,
		registry,
		univeralProtoCommit.OwnerID,
		universalProtoCommit.ModuleID,
	)
	if err != nil {
		return nil, err
	}
	commitID, err := uuid.FromString(universalProtoCommit.ID)
	if err != nil {
		return nil, err
	}
	return bufmodule.NewModuleKey(
		moduleFullName,
		commitID,
		func() (bufmodule.Digest, error) {
			return universalProtoCommit.Digest, nil
		},
	)
}

func getModuleFullNameForRegistryProtoOwnerIdProtoModuleId(
	ctx context.Context,
	v1ProtoModuleProvider *v1ProtoModuleProvider,
	v1ProtoOwnerProvider *v1ProtoOwnerProvider,
	registry string,
	protoOwnerID string,
	protoModuleID string,
) (bufmodule.ModuleFullName, error) {
	v1ProtoModule, err := v1ProtoModuleProvider.getV1ProtoModuleForModuleID(
		ctx,
		registry,
		protoModuleID,
	)
	if err != nil {
		return nil, err
	}
	v1ProtoOwner, err := v1ProtoOwnerProvider.getV1ProtoOwnerForOwnerID(
		ctx,
		registry,
		protoOwnerID,
	)
	if err != nil {
		return nil, err
	}
	var ownerName string
	switch {
	case v1ProtoOwner.GetUser() != nil:
		ownerName = v1ProtoOwner.GetUser().Name
	case v1ProtoOwner.GetOrganization() != nil:
		ownerName = v1ProtoOwner.GetOrganization().Name
	default:
		return nil, fmt.Errorf("proto Owner did not have a User or Organization: %v", v1ProtoOwner)
	}
	return bufmodule.NewModuleFullName(
		registry,
		ownerName,
		v1ProtoModule.Name,
	)
}
