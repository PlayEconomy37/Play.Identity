package password

import (
	"github.com/PlayEconomy37/Play.Identity/internal/argon2id"
)

// Password is a struct that contains the plaintext and hashed
// versions of the password for a user. The plaintext field is a *pointer* to a string,
// so that we're able to distinguish between a plaintext password not being present in
// the struct at all, versus a plaintext password which is the empty string "".
type Password struct {
	Plaintext *string
	Hash      *string
}

// Set calculates the argon2id hash of a plaintext password, and stores both
// the hash and the plaintext versions in the struct
func (p *Password) Set(plaintextPassword string) error {
	hash, err := argon2id.CreateHash(plaintextPassword, argon2id.DefaultParams)
	if err != nil {
		return err
	}

	p.Plaintext = &plaintextPassword
	p.Hash = &hash

	return nil
}

// Matches checks whether the provided plaintext password matches the
// hashed password stored in the struct, returning true if it matches and false
// otherwise.
func (p *Password) Matches(plaintextPassword string) (bool, error) {
	match, err := argon2id.ComparePasswordAndHash(plaintextPassword, *p.Hash)
	if err != nil {
		return false, err
	}

	return match, nil
}
