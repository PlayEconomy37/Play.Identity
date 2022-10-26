package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/PlayEconomy37/Play.Common/common"
	"github.com/PlayEconomy37/Play.Common/database"
	"github.com/pascaldekloe/jwt"
)

// Authenticate is a middleware used to authenticate a user before acessing a certain route.
// It extracts a JWT access token from the Authorization header and validates it.
func Authenticate(app *Application) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		publicKey, err := common.LoadRsaPublicKey(app.Config.RSA.PublicKey)
		if err != nil {
			app.Logger.Fatal(err, nil)
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add the "Vary: Authorization" header to the response. This indicates to any
			// caches that the response may vary based on the value of the Authorization
			// header in the request.
			w.Header().Add("Vary", "Authorization")

			// Retrieve the value of the Authorization header from the request. This will
			// return the empty string "" if there is no such header found.
			authorizationHeader := r.Header.Get("Authorization")

			// If there is no Authorization header found, send back a 401 Unauthorized response
			if authorizationHeader == "" {
				app.InvalidAuthenticationTokenResponse(w, r)
				return
			}

			// Otherwise, we expect the value of the Authorization header to be in the format
			// "Bearer <token>". We try to split this into its constituent parts, and if the
			// header isn't in the expected format we return a 401 Unauthorized response
			headerParts := strings.Split(authorizationHeader, " ")
			if len(headerParts) != 2 || headerParts[0] != "Bearer" {
				app.InvalidAuthenticationTokenResponse(w, r)
				return
			}

			// Extract the actual authentication token from the header parts
			token := headerParts[1]

			// Parse the JWT and extract the claims. This will return an error if the JWT
			// contents doesn't match the signature (i.e. the token has been tampered with)
			// or the algorithm isn't valid.
			claims, err := jwt.RSACheck([]byte(token), publicKey)
			if err != nil {
				app.InvalidAuthenticationTokenResponse(w, r)
				return
			}

			// Check if the JWT is still valid at this moment in time
			if !claims.Valid(time.Now()) {
				app.InvalidAuthenticationTokenResponse(w, r)
				return
			}

			// Check that the issuer is our identity service
			if claims.Issuer != app.Config.Authority {
				app.InvalidAuthenticationTokenResponse(w, r)
				return
			}

			// Check that the frontend is in the expected audiences for the JWT
			if !claims.AcceptAudience("http://localhost:3000") {
				app.InvalidAuthenticationTokenResponse(w, r)
				return
			}

			// At this point, we know that the JWT is all OK and we can trust the data in
			// it. We extract the user ID from the claims subject and convert it from a
			// string into an int64.
			userID, err := strconv.ParseInt(claims.Subject, 10, 64)
			if err != nil {
				app.ServerErrorResponse(w, r, err)
				return
			}

			// Retrieve the details of the user associated with the authentication token
			user, err := app.UsersRepository.GetByID(r.Context(), userID)
			if err != nil {
				switch {
				case errors.Is(err, database.ErrRecordNotFound):
					app.InvalidAuthenticationTokenResponse(w, r)
				default:
					app.ServerErrorResponse(w, r, err)
				}

				return
			}

			// Call the contextSetUser() helper to add the user information to the request context
			r = ContextSetUser(r, *user)

			// Call the next handler in the chain
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission is a middleware used to check if user has the right permissions to access a certain route
func RequirePermission(
	app *Application,
	codes ...string,
) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Retrieve the user from the request context
			currentUser := ContextGetUser(r)

			// Get the slice of permissions for the user
			permissions, err := app.PermissionsRepository.GetAllForUser(r.Context(), currentUser.ID)
			if err != nil {
				app.ServerErrorResponse(w, r, err)
				return
			}

			// Check if the slice includes the required permission. If it doesn't, then
			// return a 403 Forbidden response.
			for _, code := range codes {
				if !permissions.Include(code) {
					app.NotPermittedResponse(w, r)
					return
				}
			}

			// Otherwise they have the required permission so we call the next handler in
			// the chain.
			next.ServeHTTP(w, r)
		})
	}
}
