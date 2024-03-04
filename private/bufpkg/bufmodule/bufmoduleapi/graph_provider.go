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
	"io/fs"

	modulev1 "buf.build/gen/go/bufbuild/registry/protocolbuffers/go/buf/registry/module/v1"
	modulev1beta1 "buf.build/gen/go/bufbuild/registry/protocolbuffers/go/buf/registry/module/v1beta1"
	"connectrpc.com/connect"
	"github.com/bufbuild/buf/private/bufpkg/bufapi"
	"github.com/bufbuild/buf/private/bufpkg/bufmodule"
	"github.com/bufbuild/buf/private/pkg/dag"
	"github.com/bufbuild/buf/private/pkg/slicesext"
	"github.com/bufbuild/buf/private/pkg/syserror"
	"github.com/gofrs/uuid/v5"
	"go.uber.org/zap"
)

// NewGraphProvider returns a new GraphProvider for the given API client.
func NewGraphProvider(
	logger *zap.Logger,
	clientProvider interface {
		bufapi.V1GraphServiceClientProvider
		bufapi.V1ModuleServiceClientProvider
		bufapi.V1OwnerServiceClientProvider
		bufapi.V1Beta1GraphServiceClientProvider
	},
	options ...GraphProviderOption,
) bufmodule.GraphProvider {
	return newGraphProvider(logger, clientProvider, options...)
}

// GraphProviderOption is an option for a new GraphProvider.
type GraphProviderOption func(*graphProvider)

// GraphProviderWithPublicRegistry returns a new GraphProviderOption that specifies
// the hostname of the public registry. By default this is "buf.build", however in testing,
// this may be something else. This is needed to discern which which registry to make calls
// against in the case where there is >1 registries represented in the ModuleKeys - we always
// want to call the non-public registry.
func GraphProviderWithPublicRegistry(publicRegistry string) GraphProviderOption {
	return func(graphProvider *graphProvider) {
		if publicRegistry != "" {
			graphProvider.publicRegistry = publicRegistry
		}
	}
}

// *** PRIVATE ***

type graphProvider struct {
	logger         *zap.Logger
	clientProvider interface {
		bufapi.V1GraphServiceClientProvider
		bufapi.V1ModuleServiceClientProvider
		bufapi.V1OwnerServiceClientProvider
		bufapi.V1Beta1GraphServiceClientProvider
	}
	publicRegistry string
}

func newGraphProvider(
	logger *zap.Logger,
	clientProvider interface {
		bufapi.V1GraphServiceClientProvider
		bufapi.V1ModuleServiceClientProvider
		bufapi.V1OwnerServiceClientProvider
		bufapi.V1Beta1GraphServiceClientProvider
	},
	options ...GraphProviderOption,
) *graphProvider {
	graphProvider := &graphProvider{
		logger:         logger,
		clientProvider: clientProvider,
		publicRegistry: defaultPublicRegistry,
	}
	for _, option := range options {
		option(graphProvider)
	}
	return graphProvider
}

func (a *graphProvider) GetGraphForModuleKeys(
	ctx context.Context,
	moduleKeys []bufmodule.ModuleKey,
) (*dag.Graph[bufmodule.RegistryCommitID, bufmodule.ModuleKey], error) {
	graph := dag.NewGraph[bufmodule.RegistryCommitID, bufmodule.ModuleKey](bufmodule.ModuleKeyToRegistryCommitID)
	if len(moduleKeys) == 0 {
		return graph, nil
	}
	digestType, err := bufmodule.UniqueDigestTypeForModuleKeys(moduleKeys)
	if err != nil {
		return nil, err
	}

	// We don't want to persist these across calls - this could grow over time and this cache
	// isn't an LRU cache, and the information also may change over time.
	v1ProtoModuleProvider := newV1ProtoModuleProvider(a.logger, a.clientProvider)
	v1ProtoOwnerProvider := newV1ProtoOwnerProvider(a.logger, a.clientProvider)
	v1beta1ProtoGraph, err := a.getV1Beta1ProtoGraphForModuleKeys(ctx, moduleKeys, digestType)
	if err != nil {
		return nil, err
	}
	registryCommitIDToModuleKey, err := slicesext.ToUniqueValuesMapError(
		moduleKeys,
		func(moduleKey bufmodule.ModuleKey) (bufmodule.RegistryCommitID, error) {
			return bufmodule.ModuleKeyToRegistryCommitID(moduleKey), nil
		},
	)
	if err != nil {
		return nil, err
	}
	for _, v1beta1ProtoGraphCommit := range v1beta1ProtoGraph.Commits {
		v1beta1ProtoCommit := v1beta1ProtoGraphCommit.Commit
		registry := v1beta1ProtoGraphCommit.Registry
		commitID, err := uuid.FromString(v1beta1ProtoCommit.Id)
		if err != nil {
			return nil, err
		}
		registryCommitID := bufmodule.NewRegistryCommitID(registry, commitID)
		moduleKey, ok := registryCommitIDToModuleKey[registryCommitID]
		if !ok {
			universalProtoCommit, err := newUniversalProtoCommitForV1Beta1(v1beta1ProtoCommit)
			if err != nil {
				return nil, err
			}
			// This may be a transitive dependency that we don't have. In this case,
			// go out to the API and get the transitive dependency.
			moduleKey, err = getModuleKeyForUniversalProtoCommit(
				ctx,
				v1ProtoModuleProvider,
				v1ProtoOwnerProvider,
				registry,
				universalProtoCommit,
			)
			if err != nil {
				return nil, err
			}
			registryCommitIDToModuleKey[registryCommitID] = moduleKey
		}
		graph.AddNode(moduleKey)
	}
	for _, v1beta1ProtoEdge := range v1beta1ProtoGraph.Edges {
		fromRegistry := v1beta1ProtoEdge.FromNode.Registry
		fromCommitID, err := uuid.FromString(v1beta1ProtoEdge.FromNode.CommitId)
		if err != nil {
			return nil, err
		}
		fromRegistryCommitID := bufmodule.NewRegistryCommitID(fromRegistry, fromCommitID)
		fromModuleKey, ok := registryCommitIDToModuleKey[fromRegistryCommitID]
		if !ok {
			// We should always have this after our previous iteration.
			// This could be an API error, but regardless we consider it a system error here.
			return nil, syserror.Newf("did not have RegistryCommitID %v in registryCommitIDToModuleKey", fromRegistryCommitID)
		}
		toRegistry := v1beta1ProtoEdge.ToNode.Registry
		toCommitID, err := uuid.FromString(v1beta1ProtoEdge.ToNode.CommitId)
		if err != nil {
			return nil, err
		}
		toRegistryCommitID := bufmodule.NewRegistryCommitID(toRegistry, toCommitID)
		toModuleKey, ok := registryCommitIDToModuleKey[toRegistryCommitID]
		if !ok {
			// We should always have this after our previous iteration.
			// This could be an API error, but regardless we consider it a system error here.
			return nil, syserror.Newf("did not have RegistryCommitID %v in registryCommitIDToModuleKey", toRegistryCommitID)
		}
		graph.AddEdge(fromModuleKey, toModuleKey)
	}
	return graph, nil
}

func (a *graphProvider) getV1Beta1ProtoGraphForModuleKeys(
	ctx context.Context,
	moduleKeys []bufmodule.ModuleKey,
	digestType bufmodule.DigestType,
) (*modulev1beta1.Graph, error) {
	primaryRegistry, secondaryRegistry, err := getPrimarySecondaryRegistry(moduleKeys, a.publicRegistry)
	if err != nil {
		return nil, err
	}
	if secondaryRegistry == "" && digestType == bufmodule.DigestTypeB5 {
		// If we only have a single registry, invoke the new API endpoint that does not allow
		// for federation. Do this so that we can maintain federated API endpoint metrics.
		graph, err := a.getV1ProtoGraphForRegistryAndModuleKeys(ctx, primaryRegistry, moduleKeys)
		if err != nil {
			return nil, err
		}
		return v1ProtoGraphToV1Beta1ProtoGraph(primaryRegistry, graph), nil
	}

	registryCommitIDs := slicesext.Map(moduleKeys, bufmodule.ModuleKeyToRegistryCommitID)
	v1beta1ProtoDigestType, err := digestTypeToV1Beta1Proto(digestType)
	if err != nil {
		return nil, err
	}
	response, err := a.clientProvider.V1Beta1GraphServiceClient(primaryRegistry).GetGraph(
		ctx,
		connect.NewRequest(
			&modulev1beta1.GetGraphRequest{
				// TODO FUTURE: chunking
				ResourceRefs: slicesext.Map(
					registryCommitIDs,
					func(registryCommitID bufmodule.RegistryCommitID) *modulev1beta1.GetGraphRequest_ResourceRef {
						return &modulev1beta1.GetGraphRequest_ResourceRef{
							ResourceRef: &modulev1beta1.ResourceRef{
								Value: &modulev1beta1.ResourceRef_Id{
									Id: registryCommitID.CommitID.String(),
								},
							},
							Registry: registryCommitID.Registry,
						}
					},
				),
				DigestType: v1beta1ProtoDigestType,
			},
		),
	)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			// Kind of an abuse of fs.PathError. Is there a way to get a specific ModuleKey out of this?
			return nil, &fs.PathError{Op: "read", Path: err.Error(), Err: fs.ErrNotExist}
		}
		return nil, err
	}

	for _, commit := range response.Msg.Graph.Commits {
		if err := validateRegistryIsPrimaryOrSecondary(commit.Registry, primaryRegistry, secondaryRegistry); err != nil {
			return nil, err
		}
	}
	for _, edge := range response.Msg.Graph.Edges {
		if err := validateRegistryIsPrimaryOrSecondary(edge.FromNode.Registry, primaryRegistry, secondaryRegistry); err != nil {
			return nil, err
		}
		if err := validateRegistryIsPrimaryOrSecondary(edge.ToNode.Registry, primaryRegistry, secondaryRegistry); err != nil {
			return nil, err
		}
	}

	return response.Msg.Graph, nil
}

func (a *graphProvider) getV1ProtoGraphForRegistryAndModuleKeys(
	ctx context.Context,
	registry string,
	moduleKeys []bufmodule.ModuleKey,
) (*modulev1.Graph, error) {
	commitIDs := slicesext.Map(moduleKeys, bufmodule.ModuleKey.CommitID)
	response, err := a.clientProvider.V1GraphServiceClient(registry).GetGraph(
		ctx,
		connect.NewRequest(
			&modulev1.GetGraphRequest{
				// TODO FUTURE: chunking
				ResourceRefs: slicesext.Map(
					commitIDs,
					func(commitID uuid.UUID) *modulev1.ResourceRef {
						return &modulev1.ResourceRef{
							Value: &modulev1.ResourceRef_Id{
								Id: commitID.String(),
							},
						}
					},
				),
			},
		),
	)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			// Kind of an abuse of fs.PathError. Is there a way to get a specific ModuleKey out of this?
			return nil, &fs.PathError{Op: "read", Path: err.Error(), Err: fs.ErrNotExist}
		}
		return nil, err
	}
	return response.Msg.Graph, nil
}
