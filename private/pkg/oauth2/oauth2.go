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

// oauth2 package contains functionality to work with OAuth2. It is based on the
// golang.org/x/oauth2 package, limited to the functionality needed by Buf.
package oauth2

import (
	"fmt"
)

type ErrorCode string

const (
	ErrorCodeInvalidRequest       ErrorCode = "invalid_request"
	ErrorCodeInvalidClient        ErrorCode = "invalid_client"
	ErrorCodeInvalidGrant         ErrorCode = "invalid_grant"
	ErrorCodeUnauthorizedClient   ErrorCode = "unauthorized_client"
	ErrorCodeUnsupportedGrantType ErrorCode = "unsupported_grant_type"
	ErrorCodeInvalidScope         ErrorCode = "invalid_scope"
)

type Error struct {
	// ErrorCode is RFC 6749's 'error' parameter.
	ErrorCode ErrorCode `json:"error"`
	// ErrorDescription is RFC 6749's 'error_description' parameter.
	ErrorDescription string `json:"error_description,omitempty"`
	// ErrorURI is RFC 6749's 'error_uri' parameter.
	ErrorURI string `json:"error_uri,omitempty"`
}

func (e *Error) Error() string {
	s := fmt.Sprintf("oauth2: %q", e.ErrorCode)
	if e.ErrorDescription != "" {
		s += fmt.Sprintf(" %q", e.ErrorDescription)
	}
	if e.ErrorURI != "" {
		s += fmt.Sprintf(" %q", e.ErrorURI)
	}
	return s
}
