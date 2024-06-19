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

package oauth2

import (
	"net/url"
)

const (
	DeviceRegistrationPath  = "/oauth2/device_registration"
	DeviceAuthorizationPath = "/oauth2/device_authorization"
	TokenPath               = "/oauth2/token"

	DeviceAuthorizationGrantType = "urn:ietf:params:oauth:grant-type:device_code"

	ErrorCodeAuthorizationPending ErrorCode = "authorization_pending"
	ErrorCodeSlowDown             ErrorCode = "slow_down"
	ErrorCodeAccessDenied         ErrorCode = "access_denied"
	ErrorCodeExpiredToken         ErrorCode = "expired_token"
)

type DeviceRegistrationRequest struct {
	// OPTIONAL. Name of the Client to be presented to the End-User. If desired, representation of this Claim in different languages and scripts is represented as described in Section 2.1.
	ClientName string `json:"client_name"`
}

type DeviceRegistrationResponse struct {
	// REQUIRED. Unique Client Identifier. It MUST NOT be currently valid for any other registered Client.
	ClientID string `json:"client_id"`
	// OPTIONAL. Client Secret. The same Client Secret value MUST NOT be assigned to multiple Clients. This value is used by Confidential Clients to authenticate to the Token Endpoint, as described in Section 2.3.1 of OAuth 2.0, and for the derivation of symmetric encryption key values, as described in Section 10.2 of OpenID Connect Core 1.0 [OpenID.Core]. It is not needed for Clients selecting a token_endpoint_auth_method of private_key_jwt unless symmetric encryption will be used.
	ClientSecret string `json:"client_secret,omitempty"`
	// OPTIONAL. Time at which the Client Identifier was issued. Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
	ClientIDIssuedAt int `json:"client_id_issued_at"`
	// REQUIRED if client_secret is issued. Time at which the client_secret will expire or 0 if it will not expire. Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
	ClientSecretExpiresAt int `json:"client_secret_expires_at"`
}

type DeviceAuthorizationRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}

func (d *DeviceAuthorizationRequest) ToValues() url.Values {
	values := make(url.Values, 2)
	values.Set("client_id", d.ClientID)
	if d.ClientSecret != "" {
		values.Set("client_secret", d.ClientSecret)
	}
	return values
}

func (d *DeviceAuthorizationRequest) FromValues(values url.Values) error {
	d.ClientID = values.Get("client_id")
	d.ClientSecret = values.Get("client_secret")
	return nil
}

type DeviceAuthorizationResponse struct {
	// The device verification code.
	DeviceCode string `json:"device_code"`
	// The end-user verification code.
	UserCode string `json:"user_code"`
	// A short verification URI, that the device should visit to enter the user_code.
	VerificationUri string `json:"verification_uri"`
	// A verification URI that includes the "user_code".
	VerificationUriComplete string `json:"verification_uri_complete,omitempty"`
	// The lifetime in seconds of the "device_code" and "user_code".
	ExpiresIn int `json:"expires_in"`
	// The minimum amount of time in seconds that the client SHOULD wait between polling requests to the token endpoint.
	Interval int `json:"interval,omitempty"`
}

type DeviceTokenRequest struct {
	// REQUIRED. The client identifier issued to the client during the registration process described by Section 3.2.1.
	ClientID string `json:"client_id"`
	// OPTIONAL. The client secret. The client MAY omit the parameter if the client secret is an empty string.
	ClientSecret string `json:"client_secret,omitempty"`
	// REQUIRED. The device verification code.
	DeviceCode string `json:"device_code"`
	// REQUIRED. Value MUST be set to "urn:ietf:params:oauth:grant-type:device_code".
	GrantType string `json:"grant_type"`
}

func (d *DeviceTokenRequest) ToValues() url.Values {
	values := make(url.Values, 4)
	values.Set("client_id", d.ClientID)
	if d.ClientSecret != "" {
		values.Set("client_secret", d.ClientSecret)
	}
	values.Set("device_code", d.DeviceCode)
	values.Set("grant_type", d.GrantType)
	return values
}

func (d *DeviceTokenRequest) FromValues(values url.Values) error {
	d.ClientID = values.Get("client_id")
	d.ClientSecret = values.Get("client_secret")
	d.DeviceCode = values.Get("device_code")
	d.GrantType = values.Get("grant_type")
	return nil
}

type DeviceTokenResponse struct {
	// An access token that can be used to access the protected resources.
	AccessToken string `json:"access_token"`
	// The type of the token issued as described in Section 7.1. Value is case insensitive.
	TokenType string `json:"token_type"`
	// The lifetime in seconds of the access token.
	ExpiresIn int `json:"expires_in,omitempty"`
	// The refresh token, which can be used to obtain new access tokens using the same authorization grant.
	RefreshToken string `json:"refresh_token,omitempty"`
	// The scope of the access token as described in Section 3.3.
	Scope string `json:"scope,omitempty"`
}

//// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
///*
//	 HTTP/1.1 400 Bad Request
//     Content-Type: application/json;charset=UTF-8
//     Cache-Control: no-store
//     Pragma: no-cache
//
//     {
//       "error":"invalid_request"
//     }
//*/
//type DeviceErrorResponse struct {
//	Error            DeviceTokenErrorCode `json:"error"`
//	ErrorDescription string               `json:"error_description,omitempty"`
//	ErrorUri         string               `json:"error_uri,omitempty"`
//}
//
//type DeviceTokenErrorCode string
//
//const (
//	DeviceTokenErrorInvalidRequest       DeviceTokenErrorCode = "invalid_request"
//	DeviceTokenErrorInvalidClient        DeviceTokenErrorCode = "invalid_client"
//	DeviceTokenErrorInvalidGrant         DeviceTokenErrorCode = "invalid_grant"
//	DeviceTokenErrorUnauthorizedClient   DeviceTokenErrorCode = "unauthorized_client"
//	DeviceTokenErrorUnsupportedGrantType DeviceTokenErrorCode = "unsupported_grant_type"
//	DeviceTokenErrorInvalidScope         DeviceTokenErrorCode = "invalid_scope"
//	DeviceTokenErrorAuthorizationPending DeviceTokenErrorCode = "authorization_pending"
//	DeviceTokenErrorSlowDown             DeviceTokenErrorCode = "slow_down"
//	DeviceTokenErrorAccessDenied         DeviceTokenErrorCode = "access_denied"
//	DeviceTokenErrorExpiredToken         DeviceTokenErrorCode = "expired_token"
//)

/*
   error
         REQUIRED.  A single ASCII [USASCII] error code from the
         following:

         invalid_request
               The request is missing a required parameter, includes an
               unsupported parameter value (other than grant type),
               repeats a parameter, includes multiple credentials,
               utilizes more than one mechanism for authenticating the
               client, or is otherwise malformed.

         invalid_client
               Client authentication failed (e.g., unknown client, no
               client authentication included, or unsupported
               authentication method).  The authorization server MAY
               return an HTTP 401 (Unauthorized) status code to indicate
               which HTTP authentication schemes are supported.  If the
               client attempted to authenticate via the "Authorization"
               request header field, the authorization server MUST
               respond with an HTTP 401 (Unauthorized) status code and
               include the "WWW-Authenticate" response header field
               matching the authentication scheme used by the client.

         invalid_grant
               The provided authorization grant (e.g., authorization
               code, resource owner credentials) or refresh token is
               invalid, expired, revoked, does not match the redirection
               URI used in the authorization request, or was issued to
               another client.

         unauthorized_client
               The authenticated client is not authorized to use this
               authorization grant type.

         unsupported_grant_type
               The authorization grant type is not supported by the
               authorization server.


         invalid_scope
               The requested scope is invalid, unknown, malformed, or
               exceeds the scope granted by the resource owner.

         Values for the "error" parameter MUST NOT include characters
         outside the set %x20-21 / %x23-5B / %x5D-7E.

   error_description
         OPTIONAL.  Human-readable ASCII [USASCII] text providing
         additional information, used to assist the client developer in
         understanding the error that occurred.
         Values for the "error_description" parameter MUST NOT include
         characters outside the set %x20-21 / %x23-5B / %x5D-7E.

   error_uri
         OPTIONAL.  A URI identifying a human-readable web page with
         information about the error, used to provide the client
         developer with additional information about the error.
         Values for the "error_uri" parameter MUST conform to the
         URI-reference syntax and thus MUST NOT include characters
         outside the set %x21 / %x23-5B / %x5D-7E.
*/

// Encode error....

// https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
/*

   authorization_pending
      The authorization request is still pending as the end user hasn't
      yet completed the user-interaction steps (Section 3.3).  The
      client SHOULD repeat the access token request to the token
      endpoint (a process known as polling).  Before each new request,
      the client MUST wait at least the number of seconds specified by
      the "interval" parameter of the device authorization response (see
      Section 3.2), or 5 seconds if none was provided, and respect any
      increase in the polling interval required by the "slow_down"
      error.

   slow_down
      A variant of "authorization_pending", the authorization request is
      still pending and polling should continue, but the interval MUST
      be increased by 5 seconds for this and all subsequent requests.

   access_denied
      The authorization request was denied.

   expired_token
      The "device_code" has expired, and the device authorization
      session has concluded.  The client MAY commence a new device
      authorization request but SHOULD wait for user interaction before
      restarting to avoid unnecessary polling.
*/
