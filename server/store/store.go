// Package store provides PostgreSQL implementations of all core domain interfaces.
package store

import (
	"encoding/json"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/google/uuid"
)

// DB wraps a pgxpool and implements every interface defined in the core packages.
type DB struct {
	pool *pgxpool.Pool
}

// New creates a DB store from an existing pool.
func New(pool *pgxpool.Pool) *DB {
	return &DB{pool: pool}
}

// --- helpers ----------------------------------------------------------------

func uuidFromPgtype(u pgtype.UUID) uuid.UUID {
	return uuid.UUID(u.Bytes)
}

func uuidPtrFromPgtype(u pgtype.UUID) *uuid.UUID {
	if !u.Valid {
		return nil
	}
	v := uuid.UUID(u.Bytes)
	return &v
}

func unmarshalStringSlice(raw string) []string {
	if raw == "" || raw == "null" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func toTextArray(ss []string) pgtype.Array[pgtype.Text] {
	elems := make([]pgtype.Text, len(ss))
	for i, s := range ss {
		elems[i] = pgtype.Text{String: s, Valid: true}
	}
	dims := []pgtype.ArrayDimension{}
	if len(elems) > 0 {
		dims = []pgtype.ArrayDimension{{Length: int32(len(elems)), LowerBound: 1}}
	}
	return pgtype.Array[pgtype.Text]{
		Elements: elems,
		Dims:     dims,
		Valid:    true,
	}
}

func nullText(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *s, Valid: true}
}

func nullUUID(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: [16]byte(*id), Valid: true}
}
