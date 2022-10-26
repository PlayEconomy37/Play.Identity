package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/PlayEconomy37/Play.Common/database"
	"github.com/PlayEconomy37/Play.Common/events"
	"github.com/PlayEconomy37/Play.Common/filters"
	"github.com/PlayEconomy37/Play.Common/permissions"
	"github.com/PlayEconomy37/Play.Common/types"
	"github.com/PlayEconomy37/Play.Common/validator"
	"github.com/PlayEconomy37/Play.Identity/assets"
	"github.com/PlayEconomy37/Play.Identity/internal/data"
	"github.com/PlayEconomy37/Play.Identity/internal/jwt"
	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// healthCheckHandler is the handler for the "GET /healthcheck" endpoint
func (app *Application) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	env := types.Envelope{
		"status": "available",
	}

	err := app.WriteJSON(w, http.StatusOK, env, nil)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
	}
}

// registerUserHandler is the handler for the "POST /auth/register" endpoint
func (app *Application) registerUserHandler(w http.ResponseWriter, r *http.Request) {
	// Create trace for the handler
	ctx, span := app.Tracer.Start(r.Context(), "Registering user")
	defer span.End()

	// Create an anonymous struct to hold the expected data from the request body.
	var input struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	// Parse the request body into the anonymous struct
	err := app.ReadJSON(w, r, &input)
	if err != nil {
		app.BadRequestResponse(w, r, err)
		return
	}

	// Copy the data from the request body into a new User struct
	user := &data.User{
		Name:      input.Name,
		Email:     input.Email,
		Gil:       100, // Default value for all users
		Activated: false,
	}

	// Generate and store the hashed and plaintext passwords
	err = user.Password.Set(input.Password)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
		return
	}

	v := validator.New()

	// Validate the user struct and return the error messages to the client if any of
	// the checks fail
	if data.ValidateUser(v, user); v.HasErrors() {
		app.FailedValidationResponse(w, r, v.Errors)
		return
	}

	// Start transaction
	newCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	tx, err := app.UsersRepository.StartTransaction(newCtx)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
		return
	}

	// Insert the user data into the database
	err = app.UsersRepository.Insert(ctx, user, tx)
	if err != nil {
		switch {
		// If we get a ErrDuplicateEmail error, use the v.AddError() method to manually
		// add a message to the validator instance, and then call our
		// FailedValidationResponse() helper.
		case errors.Is(err, data.ErrDuplicateEmail):
			v.AddError("email", "a user with this email address already exists")
			app.FailedValidationResponse(w, r, v.Errors)
		default:
			app.ServerErrorResponse(w, r, err)
		}

		tx.Rollback()
		return
	}

	// Add the "catalog:read" and "inventory:read" permissions for the new user
	permissions := permissions.Permissions{"catalog:read", "inventory:read", "catalog:write", "inventory:write"}
	err = app.PermissionsRepository.AddForUser(ctx, user.ID, tx, permissions...)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
		tx.Rollback()
		return
	}

	// After the user record has been created in the database, generate a new activation
	// token for the user
	token, err := app.TokensRepository.New(ctx, user.ID, 3*24*time.Hour, data.ScopeActivation, tx)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
		tx.Rollback()
		return
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		app.ServerErrorResponse(w, r, err)
		return
	}

	// Send welcome email to new user
	app.Background(ctx, func(newCtx context.Context) {
		// Create trace for the handler
		_, span := app.Tracer.Start(newCtx, "Sending greetings email")
		defer span.End()

		span.SetAttributes(attribute.Int64("userID", user.ID))
		span.SetAttributes(attribute.String("email", user.Email))

		data := map[string]any{
			"activationToken": token.Plaintext,
		}

		err = app.Mailer.Send(user.Email, assets.EmbeddedFiles, "user_welcome.tmpl", data)
		if err != nil {
			app.Logger.Error(err, nil)
		}
	})

	// Publish user updated event
	event := events.UserUpdatedEvent{
		ID:          user.ID,
		Email:       user.Email,
		Permissions: permissions,
		Activated:   user.Activated,
		Version:     int32(user.Version),
	}

	js, err := json.Marshal(event)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
		return
	}

	app.UserUpdatedPublisher.Publish(ctx, js)

	env := types.Envelope{
		"user": user,
	}

	err = app.WriteJSON(w, http.StatusCreated, env, nil)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
	}
}

// createActivationTokenHandler is the handler for the "POST /auth/tokens/activation" endpoint
func (app *Application) createActivationTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Create trace for the handler
	ctx, span := app.Tracer.Start(r.Context(), "Creating activation token")
	defer span.End()

	// Parse and validate the user's email address
	var input struct {
		Email string `json:"email"`
	}

	err := app.ReadJSON(w, r, &input)
	if err != nil {
		app.BadRequestResponse(w, r, err)
		return
	}

	v := validator.New()

	if data.ValidateEmail(v, input.Email); v.HasErrors() {
		app.FailedValidationResponse(w, r, v.Errors)
		return
	}

	// Retrieve the corresponding user record for the email address
	user, err := app.UsersRepository.GetByEmail(ctx, input.Email)
	if err != nil {
		switch {
		case errors.Is(err, database.ErrRecordNotFound):
			v.AddError("email", "no matching email address found")
			app.FailedValidationResponse(w, r, v.Errors)
		default:
			app.ServerErrorResponse(w, r, err)
		}
		return
	}

	// Return an error if the user has already been activated
	if user.Activated {
		v.AddError("email", "user has already been activated")
		app.FailedValidationResponse(w, r, v.Errors)
		return
	}

	// Otherwise, create a new activation token
	token, err := app.TokensRepository.New(ctx, user.ID, 3*24*time.Hour, data.ScopeActivation, nil)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
		return
	}

	// Email the user with their new activation token
	app.Background(ctx, func(newCtx context.Context) {
		// Create trace for the handler
		_, span := app.Tracer.Start(newCtx, "Sending token activation email")
		defer span.End()

		span.SetAttributes(attribute.String("email", user.Email))

		data := map[string]any{
			"activationToken": token.Plaintext,
		}

		err = app.Mailer.Send(user.Email, assets.EmbeddedFiles, "token_activation.tmpl", data)
		if err != nil {
			app.Logger.Error(err, nil)
		}
	})

	// Send a 202 Accepted response and confirmation message to the client
	env := types.Envelope{"message": "an email will be sent to you containing activation instructions"}

	err = app.WriteJSON(w, http.StatusAccepted, env, nil)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
	}
}

// activateUserHandler is the handler for the "PUT /auth/users/activate" endpoint
func (app *Application) activateUserHandler(w http.ResponseWriter, r *http.Request) {
	// Create trace for the handler
	ctx, span := app.Tracer.Start(r.Context(), "Activating user")
	defer span.End()

	// Parse the plaintext activation token from the request body
	var input struct {
		TokenPlaintext string `json:"token"`
	}

	err := app.ReadJSON(w, r, &input)
	if err != nil {
		app.BadRequestResponse(w, r, err)
		return
	}

	// Validate the plaintext token provided
	v := validator.New()

	if data.ValidateTokenPlaintext(v, input.TokenPlaintext); v.HasErrors() {
		app.FailedValidationResponse(w, r, v.Errors)
		return
	}

	// Retrieve the details of the user associated with the token
	user, err := app.UsersRepository.GetForToken(ctx, data.ScopeActivation, input.TokenPlaintext)
	if err != nil {
		switch {
		case errors.Is(err, database.ErrRecordNotFound):
			v.AddError("token", "invalid or expired activation token")
			app.FailedValidationResponse(w, r, v.Errors)
		default:
			app.ServerErrorResponse(w, r, err)
		}
		return
	}

	span.SetAttributes(attribute.Int64("userID", user.ID))

	// Update the user's activation status
	user.Activated = true

	// Save the updated user record in our database
	err = app.UsersRepository.Update(ctx, user)
	if err != nil {
		switch {
		case errors.Is(err, database.ErrEditConflict):
			app.EditConflictResponse(w, r)
		default:
			app.ServerErrorResponse(w, r, err)
		}
		return
	}

	// If everything went successfully, then we delete all activation tokens for the user
	err = app.TokensRepository.DeleteAllForUser(ctx, data.ScopeActivation, user.ID)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
		return
	}

	// Publish user updated event
	event := events.UserUpdatedEvent{
		ID:          user.ID,
		Email:       user.Email,
		Permissions: permissions.Permissions{},
		Activated:   user.Activated,
		Version:     int32(user.Version),
	}

	js, err := json.Marshal(event)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
		return
	}

	app.UserUpdatedPublisher.Publish(ctx, js)

	env := types.Envelope{"message": "User activated successfully"}

	// Send the updated user details to the client in a JSON response.
	err = app.WriteJSON(w, http.StatusOK, env, nil)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
	}
}

// loginHandler is the handler for the "POST /auth/login" endpoint
func (app *Application) loginHandler(w http.ResponseWriter, r *http.Request) {
	// Create trace for the handler
	ctx, span := app.Tracer.Start(r.Context(), "Logging in user")
	defer span.End()

	// Parse the email and password from the request body
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err := app.ReadJSON(w, r, &input)
	if err != nil {
		app.BadRequestResponse(w, r, err)
		return
	}

	span.SetAttributes(attribute.String("email", input.Email))

	// Validate the email and password provided by the client
	v := validator.New()

	data.ValidateEmail(v, input.Email)
	data.ValidatePasswordPlaintext(v, input.Password)

	if v.HasErrors() {
		app.FailedValidationResponse(w, r, v.Errors)
		return
	}

	// Lookup the user record based on the email address. If no matching user was
	// found, then we call the app.invalidCredentialsResponse() helper to send a 401
	// Unauthorized response to the client.
	user, err := app.UsersRepository.GetByEmail(ctx, input.Email)
	if err != nil {
		switch {
		case errors.Is(err, database.ErrRecordNotFound):
			app.InvalidCredentialsResponse(w, r)
		default:
			app.ServerErrorResponse(w, r, err)
		}

		return
	}

	// Check if the provided password matches the actual password for the user
	match, err := user.Password.Matches(input.Password)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
		return
	}

	// If the passwords don't match, then we call the app.invalidCredentialsResponse()
	// helper again and return
	if !match {
		app.InvalidCredentialsResponse(w, r)
		return
	}

	// Return error if user is not activated
	if !user.Activated {
		v.AddError("email", "user is not activated")
		app.FailedValidationResponse(w, r, v.Errors)
		return
	}

	// Otherwise, if the password is correct, we generate a new access token with a 24-hour expiry time
	accessToken, err := jwt.CreateAccessToken(user.ID, app.Config.RSA.PrivateKey)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
		return
	}

	// Encode the token to JSON and send it in the response along with a 200 Created
	// status code
	err = app.WriteJSON(w, http.StatusOK, types.Envelope{"access_token": accessToken}, nil)
	if err != nil {
		app.ServerErrorResponse(w, r, err)
	}
}

// getUsersHandler is the handler for the "GET /users" endpoint
func (app *Application) getUsersHandler(w http.ResponseWriter, r *http.Request) {
	// Create trace for the handler
	ctx, span := app.Tracer.Start(r.Context(), "Retrieving users")
	defer span.End()

	// Anonymous struct used to hold the expected values from the request's query string
	var input struct {
		Name string
		filters.Filters
	}

	// Read query string
	queryString := r.URL.Query()

	// Instantiate validator
	v := validator.New()

	// Extract values from query string if they exist
	input.Name = app.ReadStringFromQueryString(queryString, "name", "")
	input.Filters.Page = app.ReadIntFromQueryString(queryString, "page", 1, v)
	input.Filters.PageSize = app.ReadIntFromQueryString(queryString, "page_size", 20, v)
	input.Filters.Sort = app.ReadStringFromQueryString(queryString, "sort", "id")

	// Add the supported sort values for this endpoint to the sort safelist
	input.Filters.SortSafelist = []string{"id", "name", "email", "-id", "-name", "-email"}

	// Validate query string
	filters.ValidateFilters(v, input.Filters)

	// Check the Validator instance for any errors
	if v.HasErrors() {
		span.SetStatus(codes.Error, "Validation failed")
		app.FailedValidationResponse(w, r, v.Errors)
		return
	}

	// Retrieve all users
	users, metadata, err := app.UsersRepository.GetAll(ctx, input.Name, input.Filters)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		app.ServerErrorResponse(w, r, err)
		return
	}

	env := types.Envelope{
		"users":    users,
		"metadata": metadata,
	}

	// Send back response
	err = app.WriteJSON(w, http.StatusOK, env, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		app.ServerErrorResponse(w, r, err)
	}
}

// getUserHandler is the handler for the "GET /users/:id" endpoint
func (app *Application) getUserHandler(w http.ResponseWriter, r *http.Request) {
	// Create trace for the handler
	ctx, span := app.Tracer.Start(r.Context(), "Retrieving user")
	defer span.End()

	// Extract id parameter from request URL parameters
	id, err := app.ReadIDParam(r)
	if err != nil {
		// Record error in the trace
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.String("id", chi.URLParamFromCtx(r.Context(), "id")))

		// Throw Not found error if extracted id is not a valid ObjectID
		app.NotFoundResponse(w, r)
		return
	}

	// Record user id in the trace
	span.SetAttributes(attribute.Int64("id", id))

	// Retrieve user with given id
	user, err := app.UsersRepository.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		switch {
		case errors.Is(err, database.ErrRecordNotFound):
			app.NotFoundResponse(w, r)
		default:
			app.ServerErrorResponse(w, r, err)
		}

		return
	}

	env := types.Envelope{
		"user": user,
	}

	err = app.WriteJSON(w, http.StatusOK, env, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		app.ServerErrorResponse(w, r, err)
	}
}

// updateUserHandler is the handler for the "PUT /users/:id" endpoint
func (app *Application) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	// Create trace for the handler
	ctx, span := app.Tracer.Start(r.Context(), "Updating user")
	defer span.End()

	// Extract id parameter from request URL parameters
	id, err := app.ReadIDParam(r)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.String("id", chi.URLParamFromCtx(r.Context(), "id")))

		// Throw Not found error if extracted id is not a valid ObjectID
		app.NotFoundResponse(w, r)
		return
	}

	// Record user id in the trace
	span.SetAttributes(attribute.Int64("id", id))

	// Retrieve user with given id
	user, err := app.UsersRepository.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		switch {
		case errors.Is(err, database.ErrRecordNotFound):
			app.NotFoundResponse(w, r)
		default:
			app.ServerErrorResponse(w, r, err)
		}

		return
	}

	// We use pointers so that we get a nil value when decoding these values from JSON.
	// This way we can check if a user has provided the key/value pair in the JSON or not.
	var input struct {
		Name  *string  `json:"name"`
		Email *string  `json:"email"`
		Gil   *float64 `json:"Gil"`
	}

	// Read request body and decode it into the input struct
	err = app.ReadJSON(w, r, &input)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		app.BadRequestResponse(w, r, err)
		return
	}

	// Copy the values from the input struct to the fetched user if they exist
	if input.Name != nil {
		user.Name = *input.Name
	}

	if input.Email != nil {
		user.Email = *input.Email
	}

	if input.Gil != nil {
		user.Gil = *input.Gil
	}

	// Initialize a new Validator instance
	v := validator.New()

	// Perform validation checks
	data.ValidateEmail(v, user.Email)
	data.ValidateName(v, user.Name)
	v.Check(user.Gil > 0, "gil", "must be greater than 0")

	if v.HasErrors() {
		span.SetStatus(codes.Error, "Validation failed")
		app.FailedValidationResponse(w, r, v.Errors)
		return
	}

	// Update user in the database
	err = app.UsersRepository.Update(ctx, user)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		switch {
		case errors.Is(err, database.ErrEditConflict):
			app.EditConflictResponse(w, r)
		default:
			app.ServerErrorResponse(w, r, err)
		}

		return
	}

	env := types.Envelope{
		"message": "User updated successfully",
	}

	err = app.WriteJSON(w, http.StatusOK, env, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		app.ServerErrorResponse(w, r, err)
	}
}

// deleteUserHandler is the handler for the "DELETE /users/:id" endpoint
func (app *Application) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	// Create trace for the handler
	ctx, span := app.Tracer.Start(r.Context(), "Deleting user")
	defer span.End()

	// Extract id parameter from request URL parameters
	id, err := app.ReadIDParam(r)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.String("id", chi.URLParamFromCtx(r.Context(), "id")))

		// Throw Not found error if extracted id is not a valid ObjectID
		app.NotFoundResponse(w, r)
		return
	}

	// Record user id in the trace
	span.SetAttributes(attribute.Int64("id", id))

	// Delete user in the database
	err = app.UsersRepository.Delete(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		switch {
		case errors.Is(err, database.ErrRecordNotFound):
			app.NotFoundResponse(w, r)
		default:
			app.ServerErrorResponse(w, r, err)
		}

		return
	}

	env := types.Envelope{
		"message": "User deleted successfully",
	}

	err = app.WriteJSON(w, http.StatusOK, env, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		app.ServerErrorResponse(w, r, err)
	}
}
