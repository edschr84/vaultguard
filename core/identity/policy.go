package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Rule is a simple allow/deny rule used by the built-in policy engine.
type Rule struct {
	Effect   string   `json:"effect"`   // "allow" | "deny"
	Actions  []string `json:"actions"`  // e.g. ["secret.read", "secret.write"]
	Resources []string `json:"resources"` // glob patterns e.g. ["ci/docker/*"]
}

// Policy represents a named set of access control rules.
type Policy struct {
	ID          uuid.UUID
	Name        string
	Description string
	RegoSource  string
	Rules       []Rule
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// PolicyStore is the DB interface for policy operations.
type PolicyStore interface {
	CreatePolicy(ctx context.Context, p CreatePolicyParams) (PolicyRow, error)
	GetPolicyByName(ctx context.Context, name string) (PolicyRow, error)
	GetPolicyByID(ctx context.Context, id uuid.UUID) (PolicyRow, error)
	UpdatePolicy(ctx context.Context, p UpdatePolicyParams) (PolicyRow, error)
	DeletePolicy(ctx context.Context, id uuid.UUID) error
	ListPolicies(ctx context.Context, limit, offset int32) ([]PolicyRow, error)
	CreatePolicyBinding(ctx context.Context, p PolicyBindingParams) (PolicyBindingRow, error)
	ListPolicyBindingsForSubject(ctx context.Context, subjectType, subjectID string) ([]PolicyBindingRow, error)
	DeletePolicyBinding(ctx context.Context, policyID uuid.UUID, subjectType, subjectID string) error
}

type PolicyRow struct {
	ID          uuid.UUID
	Name        string
	Description string
	RegoSource  string
	Rules       []byte
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type PolicyBindingRow struct {
	ID          uuid.UUID
	PolicyID    uuid.UUID
	SubjectType string
	SubjectID   string
	PolicyName  string
	Rules       []byte
	RegoSource  string
	CreatedAt   time.Time
}

type CreatePolicyParams struct {
	Name        string
	Description string
	RegoSource  string
	Rules       []Rule
}

type UpdatePolicyParams struct {
	ID          uuid.UUID
	Description *string
	RegoSource  *string
	Rules       *[]Rule
	Enabled     *bool
}

type PolicyBindingParams struct {
	PolicyID    uuid.UUID
	SubjectType string // "user" | "client" | "group"
	SubjectID   string
}

// PolicyService manages access policies and bindings.
type PolicyService struct {
	store PolicyStore
}

func NewPolicyService(store PolicyStore) *PolicyService {
	return &PolicyService{store: store}
}

// List returns a paginated list of policies.
func (s *PolicyService) List(ctx context.Context, limit, offset int32) ([]*Policy, error) {
	rows, err := s.store.ListPolicies(ctx, limit, offset)
	if err != nil {
		return nil, err
	}
	policies := make([]*Policy, 0, len(rows))
	for _, r := range rows {
		p, err := rowToPolicy(r)
		if err != nil {
			continue
		}
		policies = append(policies, p)
	}
	return policies, nil
}

// CreateOrUpdate upserts a named policy.
func (s *PolicyService) CreateOrUpdate(ctx context.Context, p CreatePolicyParams) (*Policy, error) {
	existing, err := s.store.GetPolicyByName(ctx, p.Name)
	if err == nil {
		// Update path
		rulesJSON, _ := json.Marshal(p.Rules)
		rulesStr := string(rulesJSON)
		row, err := s.store.UpdatePolicy(ctx, UpdatePolicyParams{
			ID:         existing.ID,
			RegoSource: &p.RegoSource,
			Rules:      &p.Rules,
		})
		_ = rulesStr
		if err != nil {
			return nil, err
		}
		return rowToPolicy(row)
	}

	row, err := s.store.CreatePolicy(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("create policy: %w", err)
	}
	return rowToPolicy(row)
}

// Bind associates a policy with a subject (user, client, or group).
func (s *PolicyService) Bind(ctx context.Context, policyName, subjectType, subjectID string) error {
	pol, err := s.store.GetPolicyByName(ctx, policyName)
	if err != nil {
		return fmt.Errorf("policy %q not found", policyName)
	}
	_, err = s.store.CreatePolicyBinding(ctx, PolicyBindingParams{
		PolicyID:    pol.ID,
		SubjectType: subjectType,
		SubjectID:   subjectID,
	})
	return err
}

// Unbind removes a policy binding.
func (s *PolicyService) Unbind(ctx context.Context, policyName, subjectType, subjectID string) error {
	pol, err := s.store.GetPolicyByName(ctx, policyName)
	if err != nil {
		return fmt.Errorf("policy %q not found", policyName)
	}
	return s.store.DeletePolicyBinding(ctx, pol.ID, subjectType, subjectID)
}

// Evaluate checks whether the given subject is allowed to perform action on resource.
func (s *PolicyService) Evaluate(ctx context.Context, subjectType, subjectID, action, resource string) (bool, error) {
	bindings, err := s.store.ListPolicyBindingsForSubject(ctx, subjectType, subjectID)
	if err != nil {
		return false, err
	}

	for _, b := range bindings {
		var rules []Rule
		if err := json.Unmarshal(b.Rules, &rules); err != nil {
			continue
		}
		for _, r := range rules {
			if r.Effect == "deny" && matchesAny(r.Actions, action) && matchesAny(r.Resources, resource) {
				return false, nil
			}
		}
	}
	for _, b := range bindings {
		var rules []Rule
		if err := json.Unmarshal(b.Rules, &rules); err != nil {
			continue
		}
		for _, r := range rules {
			if r.Effect == "allow" && matchesAny(r.Actions, action) && matchesAny(r.Resources, resource) {
				return true, nil
			}
		}
	}
	return false, nil
}

// matchesAny returns true if value matches any glob pattern in patterns.
func matchesAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if p == "*" || p == value {
			return true
		}
		if strings.HasSuffix(p, "*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(value, prefix) {
				return true
			}
		}
	}
	return false
}

func rowToPolicy(r PolicyRow) (*Policy, error) {
	var rules []Rule
	if len(r.Rules) > 0 {
		if err := json.Unmarshal(r.Rules, &rules); err != nil {
			return nil, fmt.Errorf("unmarshal rules: %w", err)
		}
	}
	return &Policy{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		RegoSource:  r.RegoSource,
		Rules:       rules,
		Enabled:     r.Enabled,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}, nil
}
