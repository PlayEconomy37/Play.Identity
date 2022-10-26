package data

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/PlayEconomy37/Play.Common/database"
	"github.com/PlayEconomy37/Play.Common/filters"
)

// ErrDuplicateEmail is returned when trying to create an user with a duplicate email
var ErrDuplicateEmail = errors.New("duplicate email")

// UsersRepository is a truct that holds a Postgres connection pool
type UsersRepository struct {
	db *sql.DB
}

// NewUsersRepository creates a new users repository
func NewUsersRepository(database *sql.DB) *UsersRepository {
	return &UsersRepository{db: database}
}

// StartTransaction starts a new postgres transaction
func (repo UsersRepository) StartTransaction(ctx context.Context) (*sql.Tx, error) {
	return repo.db.BeginTx(ctx, nil)
}

// Insert inserts a new record in the database
func (repo UsersRepository) Insert(ctx context.Context, user *User, tx *sql.Tx) error {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	query := `
  	INSERT INTO users (name, email, password_hash, gil, activated) 
    VALUES ($1, $2, $3, $4, $5)
    RETURNING id, version, created_at, updated_at`

	args := []any{user.Name, user.Email, user.Password.Hash, user.Gil, user.Activated}

	var row *sql.Row

	if tx != nil {
		row = tx.QueryRowContext(ctx, query, args...)
	} else {
		row = repo.db.QueryRowContext(ctx, query, args...)
	}

	err := row.Scan(
		&user.ID,
		&user.Version,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		switch {
		case err.Error() == `pq: duplicate key value violates unique constraint "users_email_key"`:
			return ErrDuplicateEmail
		default:
			return err
		}
	}

	return nil
}

// GetByID retrieves the user details from the database based on the user's id
func (repo UsersRepository) GetByID(ctx context.Context, id int64) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	query := `
		SELECT id, name, email, password_hash, activated, gil, version, created_at, updated_at
		FROM users
		WHERE id = $1`

	var user User

	err := repo.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password.Hash,
		&user.Activated,
		&user.Gil,
		&user.Version,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, database.ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &user, nil
}

// GetByEmail retrieves the user details from the database based on the user's email address
func (repo UsersRepository) GetByEmail(ctx context.Context, email string) (User, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	query := `
			SELECT id, name, email, password_hash, activated, gil, version, created_at, updated_at
			FROM users
			WHERE email = $1`

	var user User

	err := repo.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password.Hash,
		&user.Activated,
		&user.Gil,
		&user.Version,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return user, database.ErrRecordNotFound
		default:
			return user, err
		}
	}

	return user, nil
}

// Update updates the details for a specific user
func (repo UsersRepository) Update(ctx context.Context, user *User) error {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	query := `
			UPDATE users 
			SET name = $1, email = $2, password_hash = $3, activated = $4, gil = $5, version = version + 1, updated_at = now()
			WHERE id = $6 AND version = $7
			returning version`

	args := []any{
		user.Name,
		user.Email,
		user.Password.Hash,
		user.Activated,
		user.Gil,
		user.ID,
		user.Version,
	}

	err := repo.db.QueryRowContext(ctx, query, args...).Scan(&user.Version)
	if err != nil {
		switch {
		case err.Error() == `pq: duplicate key value violates unique constraint "users_email_key"`:
			return ErrDuplicateEmail
		case errors.Is(err, sql.ErrNoRows):
			return database.ErrEditConflict
		default:
			return err
		}
	}

	return nil
}

// GetForToken retrieves the user linked to the given token
func (repo UsersRepository) GetForToken(ctx context.Context, tokenScope, tokenPlaintext string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	// Calculate the SHA-256 hash of the plaintext token provided by the client.
	// Remember that this returns a byte *array* with length 32, not a slice.
	tokenHash := sha256.Sum256([]byte(tokenPlaintext))

	query := `
			SELECT users.id, users.name, users.email, users.password_hash, users.activated, users.gil, users.version, users.created_at, users.updated_at
			FROM users
			INNER JOIN tokens
			ON users.id = tokens.user_id
			WHERE tokens.hash = $1
			AND tokens.scope = $2 
			AND tokens.expiry > $3`

	// Create a slice containing the query arguments. Notice how we use the [:] operator
	// to get a slice containing the token hash, rather than passing in the array (which
	// is not supported by the pq driver).
	args := []any{tokenHash[:], tokenScope, time.Now()}

	var user User

	err := repo.db.QueryRowContext(ctx, query, args...).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password.Hash,
		&user.Activated,
		&user.Gil,
		&user.Version,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, database.ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &user, nil
}

// GetAll retrieves all users
func (repo UsersRepository) GetAll(
	ctx context.Context,
	name string,
	fs filters.Filters,
) ([]User, filters.Metadata, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	totalRecords := 0
	users := []User{}

	// We also include a secondary sort on the movie ID to ensure a
	// consistent ordering
	query := fmt.Sprintf(`
		SELECT COUNT(*) OVER(), id, name, email, activated, gil, version, created_at, updated_at
		FROM users
		WHERE (to_tsvector('simple', name) @@ plainto_tsquery('simple', $1) OR $1 = '')
		ORDER BY %s %s, id ASC
		LIMIT $2 OFFSET $3`, fs.SortColumn(), fs.SortDirectionSQL())

	rows, err := repo.db.QueryContext(
		ctx,
		query,
		name,
		fs.Limit(),
		fs.Offset(),
	)
	if err != nil {
		return nil, filters.Metadata{}, err
	}

	defer rows.Close()

	for rows.Next() {
		var user User

		err := rows.Scan(
			&totalRecords,
			&user.ID,
			&user.Name,
			&user.Email,
			&user.Activated,
			&user.Gil,
			&user.Version,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, filters.Metadata{}, err
		}

		users = append(users, user)
	}

	// When the rows.Next() loop has finished, call rows.Err() to retrieve any error
	// that was encountered during the iteration
	if err = rows.Err(); err != nil {
		return nil, filters.Metadata{}, err
	}

	// Generate a Metadata struct
	metadata := filters.CalculateMetadata(totalRecords, fs.Page, fs.PageSize)

	return users, metadata, nil
}

// Delete deletes a specific record
func (repo UsersRepository) Delete(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	query := `
		DELETE FROM users
		WHERE id = $1`

	result, err := repo.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return database.ErrRecordNotFound
	}

	return nil
}
