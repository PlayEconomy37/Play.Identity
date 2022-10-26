package data

import (
	"time"

	"github.com/PlayEconomy37/Play.Common/validator"
	"github.com/PlayEconomy37/Play.Identity/internal/password"
)

// User is a struct that defines our application's users
type User struct {
	ID        int64             `json:"id"`
	Name      string            `json:"name"`
	Email     string            `json:"email"`
	Password  password.Password `json:"-"`
	Activated bool              `json:"activated"`
	Gil       float64           `json:"gil"`
	Version   int               `json:"-"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// ValidateName validates an user's name
func ValidateName(v *validator.Validator, name string) {
	v.Check(name != "", "name", "must be provided")
	v.Check(len(name) <= 500, "name", "must not be more than 500 bytes long")
}

// ValidateEmail validates an user's email address
func ValidateEmail(v *validator.Validator, email string) {
	v.Check(email != "", "email", "must be provided")
	v.Check(validator.IsEmail(email), "email", "must be a valid email address")
}

// ValidatePasswordPlaintext validates a user's password
func ValidatePasswordPlaintext(v *validator.Validator, password string) {
	v.Check(password != "", "password", "must be provided")
	v.Check(validator.Between(len(password), 8, 72), "password", "must be at least 8 bytes long and no more than 72 bytes long")
}

// ValidateUser runs validation checks on an `User` struct
func ValidateUser(v *validator.Validator, user *User) {
	ValidateName(v, user.Name)
	ValidateEmail(v, user.Email)

	// If the plaintext password is not nil, call the standalone
	// ValidatePasswordPlaintext() helper
	if user.Password.Plaintext != nil {
		ValidatePasswordPlaintext(v, *user.Password.Plaintext)
	}

	// If the password hash is ever nil, this will be due to a logic error in our
	// codebase (probably because we forgot to set a password for the user). It's a
	// useful sanity check to include here, but it's not a problem with the data
	// provided by the client. So rather than adding an error to the validation map we
	// raise a panic instead.
	if user.Password.Hash == nil {
		panic("missing password hash for user")
	}
}
