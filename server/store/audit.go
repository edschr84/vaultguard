package store

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/vaultguard/core/vault"
)

// AuditLogRow is a returned audit log entry.
type AuditLogRow struct {
	ID        int64
	EventTime time.Time
	ActorType string
	ActorID   string
	Action    string
	Resource  string
	Outcome   string
	RemoteIP  string
	RequestID string
	Detail    []byte
}

const sqlListAuditLog = `
	SELECT id, event_time, actor_type, actor_id, action, resource,
	       outcome, COALESCE(remote_ip::text, ''), COALESCE(request_id, ''), detail
	FROM audit_log ORDER BY event_time DESC LIMIT $1 OFFSET $2`

// ListAuditLog returns paginated audit log entries.
func (db *DB) ListAuditLog(ctx context.Context, limit, offset int32) ([]AuditLogRow, error) {
	rows, err := db.pool.Query(ctx, sqlListAuditLog, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditLogRow
	for rows.Next() {
		var r AuditLogRow
		if err := rows.Scan(
			&r.ID, &r.EventTime, &r.ActorType, &r.ActorID,
			&r.Action, &r.Resource, &r.Outcome,
			&r.RemoteIP, &r.RequestID, &r.Detail,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

const sqlAppendAuditLog = `
	INSERT INTO audit_log
	    (actor_type, actor_id, action, resource, outcome, remote_ip, request_id, detail)
	VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8)`

// Log implements vault.AuditLogger.
func (db *DB) Log(ctx context.Context, event vault.AuditEvent) error {
	detail, _ := json.Marshal(event.Detail)

	var remoteIP pgtype.Text
	if ip, ok := ctx.Value(ctxKeyRemoteIP{}).(net.IP); ok && ip != nil {
		remoteIP = pgtype.Text{String: ip.String(), Valid: true}
	}
	var requestID pgtype.Text
	if rid, ok := ctx.Value(ctxKeyRequestID{}).(string); ok && rid != "" {
		requestID = pgtype.Text{String: rid, Valid: true}
	}

	_, err := db.pool.Exec(ctx, sqlAppendAuditLog,
		event.ActorType, event.ActorID, event.Action, event.Resource, event.Outcome,
		remoteIP, requestID, detail,
	)
	return err
}

// Context key types for request metadata passed to the audit logger.
type ctxKeyRemoteIP struct{}
type ctxKeyRequestID struct{}

// WithRemoteIP embeds the caller IP into a context for audit logging.
func WithRemoteIP(ctx context.Context, ip net.IP) context.Context {
	return context.WithValue(ctx, ctxKeyRemoteIP{}, ip)
}

// WithRequestID embeds a request ID into a context for audit logging.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID{}, id)
}
