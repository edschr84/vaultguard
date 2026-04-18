package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// SecretData is the in-memory representation of a secret's key-value pairs.
type SecretData map[string]string

// SecretMeta holds metadata stored alongside a secret version.
type SecretMeta map[string]any

// Secret is a fully-decrypted secret value returned to callers.
type Secret struct {
	ID        uuid.UUID
	Namespace string
	Mount     string
	Path      string
	Version   int32
	Data      SecretData
	Meta      SecretMeta
	CreatedAt time.Time
}

// SecretStore is the minimal DB interface required by the Store.
type SecretStore interface {
	CreateVaultSecret(ctx context.Context, p CreateSecretParams) (RawSecret, error)
	GetVaultSecretLatest(ctx context.Context, ns, mount, path string) (RawSecret, error)
	GetVaultSecretByVersion(ctx context.Context, ns, mount, path string, ver int32) (RawSecret, error)
	ListVaultSecretVersions(ctx context.Context, ns, mount, path string) ([]SecretVersionInfo, error)
	ListVaultSecretPaths(ctx context.Context, ns, mount string) ([]string, error)
	SoftDeleteVaultSecret(ctx context.Context, ns, mount, path string) error
	GetVaultSecretByID(ctx context.Context, id uuid.UUID) (RawSecret, error)
}

// DB types that map to sqlc-generated structs (defined here to avoid importing dbgen in tests).

type RawSecret struct {
	ID          uuid.UUID
	Namespace   string
	Mount       string
	Path        string
	Version     int32
	Ciphertext  []byte
	DataKeyEnc  []byte
	Metadata    []byte
	CreatedBy   *uuid.UUID
	CreatedAt   time.Time
	Deleted     bool
	DeletedAt   *time.Time
}

type SecretVersionInfo struct {
	ID        uuid.UUID
	Version   int32
	Metadata  []byte
	CreatedAt time.Time
}

type CreateSecretParams struct {
	Namespace  string
	Mount      string
	Path       string
	Ciphertext []byte
	DataKeyEnc []byte
	Metadata   []byte
	CreatedBy  *uuid.UUID
}

// Store provides the Vault secrets CRUD API.
type Store struct {
	db        SecretStore
	enc       *Encryptor
	leases    *LeaseManager
	auditLog  AuditLogger
}

// AuditLogger is a minimal interface for audit events.
type AuditLogger interface {
	Log(ctx context.Context, event AuditEvent) error
}

type AuditEvent struct {
	ActorType string
	ActorID   string
	Action    string
	Resource  string
	Outcome   string
	Detail    map[string]any
}

// NewStore creates a Store.
func NewStore(db SecretStore, enc *Encryptor, leases *LeaseManager, audit AuditLogger) *Store {
	return &Store{db: db, enc: enc, leases: leases, auditLog: audit}
}

// Put encrypts and writes a new secret version.
func (s *Store) Put(ctx context.Context, ns, mount, path string, data SecretData, meta SecretMeta, actorID string) (*Secret, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal data: %w", err)
	}

	ct, encDEK, err := s.enc.Encrypt(plaintext)
	if err != nil {
		s.emit(ctx, "system", actorID, "secret.put", fqPath(ns, mount, path), "failure", nil)
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	metaBytes, _ := json.Marshal(meta)

	raw, err := s.db.CreateVaultSecret(ctx, CreateSecretParams{
		Namespace:  ns,
		Mount:      mount,
		Path:       path,
		Ciphertext: ct,
		DataKeyEnc: encDEK,
		Metadata:   metaBytes,
	})
	if err != nil {
		s.emit(ctx, "system", actorID, "secret.put", fqPath(ns, mount, path), "failure", nil)
		return nil, fmt.Errorf("db create: %w", err)
	}

	s.emit(ctx, "system", actorID, "secret.put", fqPath(ns, mount, path), "success", map[string]any{"version": raw.Version})
	return rawToSecret(raw, data, meta), nil
}

// Get fetches and decrypts the latest version of a secret.
func (s *Store) Get(ctx context.Context, ns, mount, path string, actorID string) (*Secret, error) {
	return s.GetVersion(ctx, ns, mount, path, 0, actorID)
}

// GetVersion fetches a specific version (0 = latest).
func (s *Store) GetVersion(ctx context.Context, ns, mount, path string, version int32, actorID string) (*Secret, error) {
	var (
		raw RawSecret
		err error
	)
	if version == 0 {
		raw, err = s.db.GetVaultSecretLatest(ctx, ns, mount, path)
	} else {
		raw, err = s.db.GetVaultSecretByVersion(ctx, ns, mount, path, version)
	}
	if err != nil {
		s.emit(ctx, "system", actorID, "secret.get", fqPath(ns, mount, path), "failure", nil)
		return nil, fmt.Errorf("db get: %w", err)
	}

	pt, err := s.enc.Decrypt(raw.Ciphertext, raw.DataKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	var data SecretData
	if err := json.Unmarshal(pt, &data); err != nil {
		return nil, fmt.Errorf("unmarshal data: %w", err)
	}

	var meta SecretMeta
	_ = json.Unmarshal(raw.Metadata, &meta)

	s.emit(ctx, "system", actorID, "secret.get", fqPath(ns, mount, path), "success", map[string]any{"version": raw.Version})
	return rawToSecret(raw, data, meta), nil
}

// Delete soft-deletes all versions of a secret at the given path.
func (s *Store) Delete(ctx context.Context, ns, mount, path string, actorID string) error {
	if err := s.db.SoftDeleteVaultSecret(ctx, ns, mount, path); err != nil {
		s.emit(ctx, "system", actorID, "secret.delete", fqPath(ns, mount, path), "failure", nil)
		return err
	}
	s.emit(ctx, "system", actorID, "secret.delete", fqPath(ns, mount, path), "success", nil)
	return nil
}

// List returns all secret paths under the given namespace/mount prefix.
func (s *Store) List(ctx context.Context, ns, mount string) ([]string, error) {
	return s.db.ListVaultSecretPaths(ctx, ns, mount)
}

// Versions returns metadata for all versions of a path.
func (s *Store) Versions(ctx context.Context, ns, mount, path string) ([]SecretVersionInfo, error) {
	return s.db.ListVaultSecretVersions(ctx, ns, mount, path)
}

func (s *Store) emit(ctx context.Context, actorType, actorID, action, resource, outcome string, detail map[string]any) {
	if s.auditLog == nil {
		return
	}
	_ = s.auditLog.Log(ctx, AuditEvent{
		ActorType: actorType,
		ActorID:   actorID,
		Action:    action,
		Resource:  resource,
		Outcome:   outcome,
		Detail:    detail,
	})
}

func fqPath(ns, mount, path string) string {
	return fmt.Sprintf("%s/%s/%s", ns, mount, path)
}

func rawToSecret(raw RawSecret, data SecretData, meta SecretMeta) *Secret {
	return &Secret{
		ID:        raw.ID,
		Namespace: raw.Namespace,
		Mount:     raw.Mount,
		Path:      raw.Path,
		Version:   raw.Version,
		Data:      data,
		Meta:      meta,
		CreatedAt: raw.CreatedAt,
	}
}

// DynamicSecretBackend is the interface for backends that generate
// short-lived credentials on demand (e.g. PostgreSQL, AWS IAM).
type DynamicSecretBackend interface {
	// GenerateCredentials creates a new short-lived credential set.
	GenerateCredentials(ctx context.Context, role string) (SecretData, time.Duration, error)
	// RevokeCredentials deletes the credentials identified by leaseID.
	RevokeCredentials(ctx context.Context, leaseID string) error
}
