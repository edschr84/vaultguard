package oidc

// DiscoveryDocument is the JSON structure served at /.well-known/openid-configuration.
type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
}

// BuildDiscovery constructs the discovery document for the given issuer base URL.
func BuildDiscovery(issuerURL string) DiscoveryDocument {
	return DiscoveryDocument{
		Issuer:                issuerURL,
		AuthorizationEndpoint: issuerURL + "/authorize",
		TokenEndpoint:         issuerURL + "/token",
		UserinfoEndpoint:      issuerURL + "/userinfo",
		JwksURI:               issuerURL + "/.well-known/jwks.json",
		DeviceAuthorizationEndpoint: issuerURL + "/device/code",
		IntrospectionEndpoint: issuerURL + "/token/introspect",
		RevocationEndpoint:    issuerURL + "/token/revoke",
		ScopesSupported:       []string{"openid", "profile", "email", "offline_access"},
		ResponseTypesSupported: []string{"code"},
		ResponseModesSupported: []string{"query", "fragment", "form_post"},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
			"urn:ietf:params:oauth:grant-type:device_code",
		},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "jti",
			"name", "email", "email_verified",
			"preferred_username", "client_id", "scope",
		},
		CodeChallengeMethodsSupported: []string{"S256"},
	}
}
