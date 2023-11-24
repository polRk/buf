// Copyright 2020-2023 Buf Technologies, Inc.
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

package bufapimodule

import (
	"context"
	"errors"
	"io/fs"

	"connectrpc.com/connect"
	"github.com/bufbuild/buf/private/bufnew/bufmodule"
	registryv1alpha1 "github.com/bufbuild/buf/private/gen/proto/go/buf/alpha/registry/v1alpha1"
	"go.uber.org/zap"
)

type moduleResolver struct {
	logger                        *zap.Logger
	repositoryCommitClientFactory RepositoryCommitServiceClientFactory
}

func newModuleResolver(
	logger *zap.Logger,
	repositoryCommitClientFactory RepositoryCommitServiceClientFactory,
) *moduleResolver {
	return &moduleResolver{
		logger:                        logger,
		repositoryCommitClientFactory: repositoryCommitClientFactory,
	}
}

func (m *moduleResolver) GetModulePin(ctx context.Context, moduleRef bufmodule.ModuleRef) (bufmoduleref.ModulePin, error) {
	repositoryCommitService := m.repositoryCommitClientFactory(moduleRef.Registry())
	resp, err := repositoryCommitService.GetRepositoryCommitByReference(
		ctx,
		connect.NewRequest(&registryv1alpha1.GetRepositoryCommitByReferenceRequest{
			RepositoryOwner: moduleRef.Owner(),
			RepositoryName:  moduleRef.Name(),
			Reference:       moduleRef.Reference(),
		}),
	)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			// Required by ModuleResolver interface spec
			return nil, &fs.PathError{Op: "read", Path: moduleRef.String(), Err: fs.ErrNotExist}
		}
		return nil, err
	}
	if resp.Msg.RepositoryCommit == nil {
		return nil, errors.New("empty response")
	}
	return bufmoduleref.NewModulePin(
		moduleRef.Registry(),
		moduleRef.Owner(),
		moduleRef.Name(),
		resp.Msg.RepositoryCommit.Name,
		resp.Msg.RepositoryCommit.ManifestDigest,
	)
}
