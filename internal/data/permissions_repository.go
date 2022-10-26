package data

import (
	"context"
	"database/sql"

	"github.com/PlayEconomy37/Play.Common/permissions"
	"github.com/lib/pq"
)

// PermissionsRepository is a truct that holds a Postgres connection pool
type PermissionsRepository struct {
	db *sql.DB
}

// NewPermissionsRepository creates a new permissions repository
func NewPermissionsRepository(database *sql.DB) *PermissionsRepository {
	return &PermissionsRepository{db: database}
}

// GetAllForUser returns all permission codes for a specific user in a
// Permissions slice
func (repo PermissionsRepository) GetAllForUser(ctx context.Context, userID int64) (permissions.Permissions, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	query := `
    SELECT permissions.code
    FROM permissions
    INNER JOIN users_permissions ON users_permissions.permission_id = permissions.id
    INNER JOIN users ON users_permissions.user_id = users.id
    WHERE users.id = $1`

	rows, err := repo.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var permissions permissions.Permissions

	for rows.Next() {
		var permission string

		err := rows.Scan(&permission)
		if err != nil {
			return nil, err
		}

		permissions = append(permissions, permission)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return permissions, nil
}

// AddForUser adds the provided permission codes for a specific user. Notice that we're using a
// variadic parameter for the codes so that we can assign multiple permissions in a
// single call.
func (repo PermissionsRepository) AddForUser(ctx context.Context, userID int64, tx *sql.Tx, codes ...string) error {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	query := `
		INSERT INTO users_permissions
		SELECT $1, permissions.id FROM permissions WHERE permissions.code = ANY($2)`

	var err error

	if tx != nil {
		_, err = tx.ExecContext(ctx, query, userID, pq.Array(codes))
	} else {
		_, err = repo.db.ExecContext(ctx, query, userID, pq.Array(codes))
	}

	return err
}
