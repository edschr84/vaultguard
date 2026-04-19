package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

const (
	argon2Memory      = 64 * 1024 // 64 MB
	argon2Iterations  = 3
	argon2Parallelism = 2
	argon2KeyLen      = 32
	argon2SaltLen     = 16
)

// User represents an identity principal.
type User struct {
	ID            uuid.UUID
	Username      string
	Email         string
	DisplayName   string
	Enabled       bool
	EmailVerified bool
	Metadata      map[string]any
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// UserStore is the minimal DB interface for user operations.
type UserStore interface {
	CreateUser(ctx context.Context, p CreateUserParams) (UserRow, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (UserRow, error)
	GetUserByEmail(ctx context.Context, email string) (UserRow, error)
	GetUserByUsername(ctx context.Context, username string) (UserRow, error)
	UpdateUser(ctx context.Context, p UpdateUserParams) (UserRow, error)
	UpdateUserPassword(ctx context.Context, id uuid.UUID, hash string) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
	ListUsers(ctx context.Context, limit, offset int32) ([]UserRow, error)
}

type UserRow struct {
	ID            uuid.UUID
	Username      string
	Email         string
	PasswordHash  string
	DisplayName   string
	Enabled       bool
	EmailVerified bool
	Metadata      []byte
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type CreateUserParams struct {
	Username    string
	Email       string
	Password    string // plaintext — will be hashed
	DisplayName string
}

type UpdateUserParams struct {
	ID            uuid.UUID
	Username      *string
	Email         *string
	DisplayName   *string
	Enabled       *bool
	EmailVerified *bool
}

// UserService manages user lifecycle.
type UserService struct {
	store UserStore
}

func NewUserService(store UserStore) *UserService {
	return &UserService{store: store}
}

// Create registers a new user with an Argon2id-hashed password.
func (s *UserService) Create(ctx context.Context, p CreateUserParams) (*User, error) {
	if p.Username == "" || p.Email == "" || p.Password == "" {
		return nil, fmt.Errorf("username, email, and password are required")
	}

	hash, err := hashPassword(p.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	row, err := s.store.CreateUser(ctx, CreateUserParams{
		Username:    p.Username,
		Email:       p.Email,
		Password:    hash,
		DisplayName: p.DisplayName,
	})
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return rowToUser(row), nil
}

// Authenticate validates a password against the stored Argon2id hash.
func (s *UserService) Authenticate(ctx context.Context, usernameOrEmail, password string) (*User, error) {
	var (
		row UserRow
		err error
	)
	// Try email first, fall back to username.
	row, err = s.store.GetUserByEmail(ctx, usernameOrEmail)
	if err != nil {
		row, err = s.store.GetUserByUsername(ctx, usernameOrEmail)
		if err != nil {
			return nil, fmt.Errorf("invalid credentials")
		}
	}

	if !row.Enabled {
		return nil, fmt.Errorf("account disabled")
	}

	if !verifyPassword(password, row.PasswordHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	return rowToUser(row), nil
}

// GetByID fetches a user by UUID.
func (s *UserService) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	row, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return rowToUser(row), nil
}

// Update modifies mutable user fields.
func (s *UserService) Update(ctx context.Context, p UpdateUserParams) (*User, error) {
	row, err := s.store.UpdateUser(ctx, p)
	if err != nil {
		return nil, err
	}
	return rowToUser(row), nil
}

// ChangePassword replaces a user's password after verifying the current one.
func (s *UserService) ChangePassword(ctx context.Context, id uuid.UUID, current, newPw string) error {
	row, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if !verifyPassword(current, row.PasswordHash) {
		return fmt.Errorf("current password is incorrect")
	}
	hash, err := hashPassword(newPw)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	return s.store.UpdateUserPassword(ctx, id, hash)
}

// Delete permanently removes a user.
func (s *UserService) Delete(ctx context.Context, id uuid.UUID) error {
	return s.store.DeleteUser(ctx, id)
}

// List returns a paginated list of users.
func (s *UserService) List(ctx context.Context, limit, offset int32) ([]*User, error) {
	rows, err := s.store.ListUsers(ctx, limit, offset)
	if err != nil {
		return nil, err
	}
	users := make([]*User, len(rows))
	for i, r := range rows {
		users[i] = rowToUser(r)
	}
	return users, nil
}

// hashPassword produces an Argon2id hash encoded as base64(salt):base64(hash).
func hashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLen)
	return base64.RawStdEncoding.EncodeToString(salt) + ":" + base64.RawStdEncoding.EncodeToString(h), nil
}

// verifyPassword returns true if the password matches the stored Argon2id hash.
func verifyPassword(password, encoded string) bool {
	parts := strings.SplitN(encoded, ":", 2)
	if len(parts) != 2 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLen)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func rowToUser(r UserRow) *User {
	return &User{
		ID:            r.ID,
		Username:      r.Username,
		Email:         r.Email,
		DisplayName:   r.DisplayName,
		Enabled:       r.Enabled,
		EmailVerified: r.EmailVerified,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
}
