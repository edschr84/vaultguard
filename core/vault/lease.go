package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// LeaseStore is the minimal DB interface used by the lease manager.
type LeaseStore interface {
	CreateLease(ctx context.Context, params CreateLeaseParams) (Lease, error)
	GetLeaseByLeaseID(ctx context.Context, leaseID string) (Lease, error)
	RenewLease(ctx context.Context, leaseID string, newExpiry time.Time) (Lease, error)
	RevokeLease(ctx context.Context, leaseID string) error
}

// Lease is a local value type mirroring the DB model (avoids hard import of dbgen).
type Lease struct {
	LeaseID    string
	SecretID   uuid.UUID
	IssuedTo   string
	ExpiresAt  time.Time
	Renewable  bool
	Revoked    bool
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

// CreateLeaseParams mirrors the sqlc-generated params struct.
type CreateLeaseParams struct {
	LeaseID   string
	SecretID  uuid.UUID
	IssuedTo  string
	ExpiresAt time.Time
	Renewable bool
}

// LeaseManager manages the lifecycle of secret leases.
type LeaseManager struct {
	store      LeaseStore
	maxTTL     time.Duration
	defaultTTL time.Duration
}

// NewLeaseManager creates a LeaseManager with configurable TTL bounds.
func NewLeaseManager(store LeaseStore, defaultTTL, maxTTL time.Duration) *LeaseManager {
	if defaultTTL == 0 {
		defaultTTL = time.Hour
	}
	if maxTTL == 0 {
		maxTTL = 24 * time.Hour
	}
	return &LeaseManager{store: store, defaultTTL: defaultTTL, maxTTL: maxTTL}
}

// Issue creates a new lease for a secret.
func (lm *LeaseManager) Issue(ctx context.Context, secretID uuid.UUID, issuedTo string, ttl time.Duration) (Lease, error) {
	if ttl == 0 {
		ttl = lm.defaultTTL
	}
	if ttl > lm.maxTTL {
		ttl = lm.maxTTL
	}
	lid := "lease:" + uuid.New().String()
	return lm.store.CreateLease(ctx, CreateLeaseParams{
		LeaseID:   lid,
		SecretID:  secretID,
		IssuedTo:  issuedTo,
		ExpiresAt: time.Now().Add(ttl),
		Renewable: true,
	})
}

// Renew extends an existing lease by the given TTL increment.
func (lm *LeaseManager) Renew(ctx context.Context, leaseID string, increment time.Duration) (Lease, error) {
	lease, err := lm.store.GetLeaseByLeaseID(ctx, leaseID)
	if err != nil {
		return Lease{}, fmt.Errorf("get lease: %w", err)
	}
	if lease.Revoked {
		return Lease{}, fmt.Errorf("lease %s is revoked", leaseID)
	}
	if !lease.Renewable {
		return Lease{}, fmt.Errorf("lease %s is not renewable", leaseID)
	}
	if time.Now().After(lease.ExpiresAt) {
		return Lease{}, fmt.Errorf("lease %s has expired", leaseID)
	}
	if increment == 0 {
		increment = lm.defaultTTL
	}
	newExpiry := time.Now().Add(increment)
	if newExpiry.Sub(lease.CreatedAt) > lm.maxTTL {
		newExpiry = lease.CreatedAt.Add(lm.maxTTL)
	}
	return lm.store.RenewLease(ctx, leaseID, newExpiry)
}

// Revoke cancels a lease immediately.
func (lm *LeaseManager) Revoke(ctx context.Context, leaseID string) error {
	return lm.store.RevokeLease(ctx, leaseID)
}
