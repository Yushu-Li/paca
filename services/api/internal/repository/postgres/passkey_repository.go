package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	mfadom "github.com/Paca-AI/api/internal/domain/mfa"
)

// PasskeyRepository is the sqlx implementation of mfadom.PasskeyStore.
type PasskeyRepository struct {
	db *sqlx.DB
}

// NewPasskeyRepository returns a new PasskeyRepository.
func NewPasskeyRepository(db *sqlx.DB) *PasskeyRepository { return &PasskeyRepository{db: db} }

type passkeyRow struct {
	ID           string       `db:"id"`
	UserID       string       `db:"user_id"`
	CredentialID []byte       `db:"credential_id"`
	Name         string       `db:"name"`
	Credential   []byte       `db:"credential"`
	CreatedAt    time.Time    `db:"created_at"`
	LastUsedAt   sql.NullTime `db:"last_used_at"`
}

// ListPasskeys returns the user's passkeys, oldest first.
func (r *PasskeyRepository) ListPasskeys(ctx context.Context, userID uuid.UUID) ([]mfadom.Passkey, error) {
	var rows []passkeyRow
	if err := r.db.SelectContext(ctx, &rows, `
		SELECT id, user_id, credential_id, name, credential, created_at, last_used_at
		FROM user_passkeys WHERE user_id = $1 ORDER BY created_at, id`, userID.String()); err != nil {
		return nil, fmt.Errorf("passkey repo: list: %w", err)
	}
	out := make([]mfadom.Passkey, 0, len(rows))
	for _, row := range rows {
		id, err := uuid.Parse(row.ID)
		if err != nil {
			return nil, fmt.Errorf("passkey repo: parse id: %w", err)
		}
		p := mfadom.Passkey{
			ID: id, UserID: userID, Name: row.Name, CredentialID: row.CredentialID,
			Credential: row.Credential, CreatedAt: row.CreatedAt,
		}
		if row.LastUsedAt.Valid {
			t := row.LastUsedAt.Time
			p.LastUsedAt = &t
		}
		out = append(out, p)
	}
	return out, nil
}

// AddPasskey inserts a passkey.
func (r *PasskeyRepository) AddPasskey(ctx context.Context, p *mfadom.Passkey) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO user_passkeys (id, user_id, credential_id, name, credential)
		VALUES ($1, $2, $3, $4, $5::jsonb)`,
		p.ID.String(), p.UserID.String(), p.CredentialID, p.Name, p.Credential)
	if err != nil {
		return fmt.Errorf("passkey repo: add: %w", err)
	}
	return nil
}

// UpdatePasskeyCredential stores the refreshed credential record.
func (r *PasskeyRepository) UpdatePasskeyCredential(ctx context.Context, id uuid.UUID, credential []byte, usedAt time.Time) error {
	if _, err := r.db.ExecContext(ctx, `
		UPDATE user_passkeys SET credential = $2::jsonb, last_used_at = $3 WHERE id = $1`,
		id.String(), credential, usedAt); err != nil {
		return fmt.Errorf("passkey repo: update: %w", err)
	}
	return nil
}

// DeletePasskey removes one of the user's passkeys.
func (r *PasskeyRepository) DeletePasskey(ctx context.Context, userID, id uuid.UUID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM user_passkeys WHERE id = $1 AND user_id = $2`,
		id.String(), userID.String())
	if err != nil {
		return fmt.Errorf("passkey repo: delete: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return mfadom.ErrPasskeyNotFound
	}
	return nil
}

// DeleteUserPasskeys removes every passkey of the user; none is a no-op.
func (r *PasskeyRepository) DeleteUserPasskeys(ctx context.Context, userID uuid.UUID) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM user_passkeys WHERE user_id = $1`, userID.String()); err != nil {
		return fmt.Errorf("passkey repo: delete all: %w", err)
	}
	return nil
}

var _ mfadom.PasskeyStore = (*PasskeyRepository)(nil)
