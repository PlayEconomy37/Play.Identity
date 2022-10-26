package data

import (
	"context"
	"database/sql"
	"time"
)

// TokensRepository is a truct that holds a Postgres connection pool
type TokensRepository struct {
	db *sql.DB
}

// NewTokensRepository creates a new tokens repository
func NewTokensRepository(database *sql.DB) *TokensRepository {
	return &TokensRepository{db: database}
}

// New is a shortcut which creates a new Token struct and then inserts the
// data in the tokens table.
func (repo TokensRepository) New(ctx context.Context, userID int64, ttl time.Duration, scope string, tx *sql.Tx) (*Token, error) {
	token, err := generateToken(userID, ttl, scope)
	if err != nil {
		return nil, err
	}

	err = repo.Insert(ctx, token, tx)
	return token, err
}

// Insert inserts a new record in the database
func (repo TokensRepository) Insert(ctx context.Context, token *Token, tx *sql.Tx) error {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	query := `
  	INSERT INTO tokens (hash, user_id, expiry, scope) 
    VALUES ($1, $2, $3, $4)`

	args := []any{token.Hash, token.UserID, token.Expiry, token.Scope}

	var err error

	if tx != nil {
		_, err = tx.ExecContext(ctx, query, args...)
	} else {
		_, err = repo.db.ExecContext(ctx, query, args...)
	}

	return err
}

// GetAllForUser retrieves all tokens for a specific user and scope
func (repo TokensRepository) GetAllForUser(ctx context.Context, scope string, userID int64) ([]Token, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	var tokens []Token

	query := `
		SELECT hash, user_id, expiry, scope FROM tokens 
		WHERE scope = $1 AND user_id = $2
		order by expiry DESC`

	rows, err := repo.db.QueryContext(ctx, query, scope, userID)
	if err != nil {
		return tokens, err
	}

	defer rows.Close()

	for rows.Next() {
		var token Token

		err := rows.Scan(
			&token.Hash,
			&token.UserID,
			&token.Expiry,
			&token.Scope,
		)
		if err != nil {
			return tokens, err
		}

		tokens = append(tokens, token)
	}

	// Call rows.Err() to retrieve any error that was encountered during the iteration
	if err = rows.Err(); err != nil {
		return tokens, err
	}

	return tokens, nil
}

// DeleteAllForUser deletes all tokens for a specific user and scope
func (repo TokensRepository) DeleteAllForUser(ctx context.Context, scope string, userID int64) error {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	query := `
		DELETE FROM tokens 
		WHERE scope = $1 AND user_id = $2`

	_, err := repo.db.ExecContext(ctx, query, scope, userID)

	return err
}
