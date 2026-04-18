package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ClientType distinguishes confidential from public OAuth2 clients.
type ClientType string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
)

// GrantType represents an OAuth2 grant type.
type GrantType string

const (
	GrantAuthorizationCode GrantType = "authorization_code"
	GrantClientCredentials GrantType = "client_credentials"
	GrantRefreshToken      GrantType = "refresh_token"
	GrantDeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

// Client is an OAuth2/OIDC client application registration.
type Client struct {
	ID               uuid.UUID
	ClientID         string
	Name             string
	Type             ClientType
	RedirectURIs     []string
	AllowedScopes    []string
	AllowedGrants    []GrantType
	AccessTokenTTL   int32  // seconds
	RefreshTokenTTL  int32  // seconds
	Enabled          bool
	Metadata         map[string]any
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// ClientStore is the minimal DB interface for client operations.
type ClientStore interface {
	CreateOAuthClient(ctx context.Context, p CreateClientParams) (ClientRow, error)
	GetOAuthClientByClientID(ctx context.Context, clientID string) (ClientRow, error)
	GetOAuthClientByID(ctx context.Context, id uuid.UUID) (ClientRow, error)
	UpdateOAuthClient(ctx context.Context, p UpdateClientParams) (ClientRow, error)
	DeleteOAuthClient(ctx context.Context, id uuid.UUID) error
	ListOAuthClients(ctx context.Context, limit, offset int32) ([]ClientRow, error)
}

type ClientRow struct {
	ID               uuid.UUID
	ClientID         string
	ClientSecretHash *string
	Name             string
	ClientType       string
	RedirectURIs     []string
	AllowedScopes    []string
	AllowedGrants    []string
	AccessTokenTTL   int32
	RefreshTokenTTL  int32
	Enabled          bool
	Metadata         []byte
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type CreateClientParams struct {
	ClientID         string
	ClientSecretHash *string // nil for public clients
	Name             string
	Type             ClientType
	RedirectURIs     []string
	AllowedScopes    []string
	AllowedGrants    []GrantType
	AccessTokenTTL   int32
	RefreshTokenTTL  int32
}

type UpdateClientParams struct {
	ID              uuid.UUID
	Name            *string
	RedirectURIs    *[]string
	AllowedScopes   *[]string
	AllowedGrants   *[]GrantType
	AccessTokenTTL  *int32
	RefreshTokenTTL *int32
	Enabled         *bool
}

// ClientRegistration is the result of RegisterClient, including the raw secret.
type ClientRegistration struct {
	Client       *Client
	ClientSecret string // plaintext, shown once
}

// ClientService manages OAuth2 client lifecycle.
type ClientService struct {
	store ClientStore
}

func NewClientService(store ClientStore) *ClientService {
	return &ClientService{store: store}
}

// Register creates a new OAuth2 client, returning the plaintext secret once.
func (s *ClientService) Register(ctx context.Context, p CreateClientParams) (*ClientRegistration, error) {
	if p.Name == "" {
		return nil, fmt.Errorf("client name is required")
	}
	if len(p.AllowedScopes) == 0 {
		p.AllowedScopes = []string{"openid", "profile", "email"}
	}
	if len(p.AllowedGrants) == 0 {
		p.AllowedGrants = []GrantType{GrantAuthorizationCode, GrantRefreshToken}
	}
	if p.AccessTokenTTL == 0 {
		p.AccessTokenTTL = 900
	}
	if p.RefreshTokenTTL == 0 {
		p.RefreshTokenTTL = 86400
	}

	var rawSecret, secretHash string
	if p.Type != ClientTypePublic {
		var err2 error
		rawSecret, secretHash, err2 = generateClientSecret()
		if err2 != nil {
			return nil, fmt.Errorf("generate secret: %w", err2)
		}
	}

	var secretHashPtr *string
	if secretHash != "" {
		secretHashPtr = &secretHash
	}

	row, err := s.store.CreateOAuthClient(ctx, CreateClientParams{
		ClientID:         generateClientID(),
		ClientSecretHash: secretHashPtr,
		Name:             p.Name,
		Type:             p.Type,
		RedirectURIs:     p.RedirectURIs,
		AllowedScopes:    p.AllowedScopes,
		AllowedGrants:    p.AllowedGrants,
		AccessTokenTTL:   p.AccessTokenTTL,
		RefreshTokenTTL:  p.RefreshTokenTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	return &ClientRegistration{
		Client:       rowToClient(row),
		ClientSecret: rawSecret,
	}, nil
}

// GetByClientID fetches a client by its OAuth2 client_id string.
func (s *ClientService) GetByClientID(ctx context.Context, clientID string) (*Client, error) {
	row, err := s.store.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return rowToClient(row), nil
}

// ValidateSecret checks a plaintext secret against the stored Argon2id hash.
func (s *ClientService) ValidateSecret(ctx context.Context, clientID, secret string) bool {
	row, err := s.store.GetOAuthClientByClientID(ctx, clientID)
	if err != nil || row.ClientSecretHash == nil {
		return false
	}
	return verifyPassword(secret, *row.ClientSecretHash)
}

// List returns a paginated list of clients.
func (s *ClientService) List(ctx context.Context, limit, offset int32) ([]*Client, error) {
	rows, err := s.store.ListOAuthClients(ctx, limit, offset)
	if err != nil {
		return nil, err
	}
	clients := make([]*Client, len(rows))
	for i, r := range rows {
		clients[i] = rowToClient(r)
	}
	return clients, nil
}

// Delete permanently removes a client.
func (s *ClientService) Delete(ctx context.Context, id uuid.UUID) error {
	return s.store.DeleteOAuthClient(ctx, id)
}

func generateClientID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateClientSecret() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	hash, err = hashPassword(raw)
	return raw, hash, err
}

func rowToClient(r ClientRow) *Client {
	grants := make([]GrantType, len(r.AllowedGrants))
	for i, g := range r.AllowedGrants {
		grants[i] = GrantType(g)
	}
	return &Client{
		ID:              r.ID,
		ClientID:        r.ClientID,
		Name:            r.Name,
		Type:            ClientType(r.ClientType),
		RedirectURIs:    r.RedirectURIs,
		AllowedScopes:   r.AllowedScopes,
		AllowedGrants:   grants,
		AccessTokenTTL:  r.AccessTokenTTL,
		RefreshTokenTTL: r.RefreshTokenTTL,
		Enabled:         r.Enabled,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}
