package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/PlayEconomy37/Play.Common/common"
	"github.com/PlayEconomy37/Play.Common/configuration"
	"github.com/PlayEconomy37/Play.Common/database"
	"github.com/PlayEconomy37/Play.Common/events"
	"github.com/PlayEconomy37/Play.Common/filters"
	"github.com/PlayEconomy37/Play.Common/logger"
	"github.com/PlayEconomy37/Play.Common/mailer"
	"github.com/PlayEconomy37/Play.Common/opentelemetry"
	"github.com/PlayEconomy37/Play.Identity/assets"
	"github.com/PlayEconomy37/Play.Identity/internal/data"
	"github.com/PlayEconomy37/Play.Identity/internal/rabbitmq"
	smtpmock "github.com/mocktools/go-smtp-mock"
)

var tracerProvider = opentelemetry.SetupTracer(true)
var tokenRegex = regexp.MustCompile(`--------------------------\r\n(.*?)\r\n--------------------------`)

// Create a newTestApplication helper which returns an instance of our
// application struct with some modifications for tests
func newTestApplication(t *testing.T) (*Application, func(), *smtpmock.Server) {
	// Setup logger
	var output io.Writer
	logFlag := os.Getenv("TEST_LOG")

	if logFlag != "" {
		output = os.Stdout
	} else {
		output = io.Discard
	}

	logger := logger.New(output, logger.LevelInfo)

	// Read configuration
	config, err := configuration.LoadConfig("../../config/test.json")
	if err != nil {
		t.Fatal(err, nil)
	}

	// Create test database
	conn, err := sql.Open("postgres", "postgres://postgres:password@localhost:5433?sslmode=disable")
	if err != nil {
		logger.Fatal(err, nil)
	}

	_, err = conn.Exec("CREATE DATABASE identity_test;")
	if err != nil {
		logger.Fatal(err, nil)
	}

	// Start Postgres
	db, err := database.NewPostgresDB(config, true, assets.EmbeddedFiles)
	if err != nil {
		logger.Fatal(err, nil)
	}

	// Create and start mock email server
	mockMailServer := smtpmock.New(smtpmock.ConfigurationAttr{
		LogToStdout:       false,
		LogServerActivity: false,
	})

	if err := mockMailServer.Start(); err != nil {
		logger.Fatal(err, nil)
	}

	// Server's port will be assigned dynamically after server.Start() when portNumber wasn't specified
	hostAddress, portNumber := "127.0.0.1", mockMailServer.PortNumber

	// Create mailer instance with mock mail server settings
	mailer := mailer.New(hostAddress, portNumber, config.SMTP.Username, config.SMTP.Password, config.SMTP.Sender)

	// Connect to RabbitMQ
	rabbitMQConnection, err := events.NewRabbitMQConnection(config)
	if err != nil {
		logger.Fatal(err, nil)
	}

	// Create users repository
	usersRepository := data.NewUsersRepository(db)

	// Create UpdatedUserPublisher
	userUpdatedPublisher, err := rabbitmq.NewUserUpdatedPublisher(rabbitMQConnection, usersRepository)
	if err != nil {
		logger.Fatal(err, nil)
	}

	// Database cleanup function
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Delete test database and disconnect from postgres
		_, err := conn.ExecContext(ctx, "DROP DATABASE identity_test WITH (FORCE);")
		if err != nil {
			t.Fatal(err, nil)
		}

		if err = conn.Close(); err != nil {
			t.Fatal(err, nil)
		}

		if err = db.Close(); err != nil {
			t.Fatal(err, nil)
		}

		if err = rabbitMQConnection.Close(); err != nil {
			t.Fatal(err, nil)
		}

		// Shutdown opentelemetry tracer
		if err := tracerProvider.Shutdown(ctx); err != nil {
			t.Error(err, nil)
		}
	}

	return &Application{
		App: common.App{
			Config: config,
			Logger: logger,
			Tracer: tracerProvider.Tracer(config.ServiceName),
		},
		UsersRepository:       usersRepository,
		TokensRepository:      data.NewTokensRepository(db),
		PermissionsRepository: data.NewPermissionsRepository(db),
		UserUpdatedPublisher:  userUpdatedPublisher,
		Mailer:                mailer,
	}, cleanup, mockMailServer
}

// Define a custom testServer type which anonymously embeds a httptest.Server
// instance.
type testServer struct {
	*httptest.Server
}

// Create a newTestServer helper which initializes and returns a new instance
// of our custom testServer type
func newTestServer(t *testing.T, router http.Handler) *testServer {
	ts := httptest.NewServer(router)

	return &testServer{ts}
}

// makeRequest is a helper method that creates a request with the given method and body
func (ts *testServer) makeRequest(t *testing.T, method string, urlPath string, body map[string]any, useAuthHeader bool, accessToken string) (int, http.Header, []byte) {
	var requestBody io.Reader

	if len(body) != 0 {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}

		requestBody = bytes.NewBuffer(jsonBody)
	} else {
		requestBody = nil
	}

	// Create HTTP request
	req, err := http.NewRequest(method, ts.URL+urlPath, requestBody)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Set Authorization header if `useAuthHeader` is true
	if useAuthHeader {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	}

	// Make PUT request to given route
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer res.Body.Close()

	// Read the response body
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	// Return the response status, headers and body
	return res.StatusCode, res.Header, resBody
}

// get is a helper method for sending GET requests to the test server
func (ts *testServer) get(t *testing.T, urlPath string, useAuthHeader bool, accessToken string) (int, http.Header, []byte) {
	return ts.makeRequest(t, "GET", urlPath, map[string]any{}, useAuthHeader, accessToken)
}

// post is a helper method for sending POST requests to the test server
func (ts *testServer) post(t *testing.T, urlPath string, body map[string]any, useAuthHeader bool, accessToken string) (int, http.Header, []byte) {
	return ts.makeRequest(t, "POST", urlPath, body, useAuthHeader, accessToken)
}

// put is a helper method for sending PUT requests to the test server
func (ts *testServer) put(t *testing.T, urlPath string, body map[string]any, useAuthHeader bool, accessToken string) (int, http.Header, []byte) {
	return ts.makeRequest(t, "PUT", urlPath, body, useAuthHeader, accessToken)
}

// delete is a helper method for sending DELETE requests to the test server
func (ts *testServer) delete(t *testing.T, urlPath string, useAuthHeader bool, accessToken string) (int, http.Header, []byte) {
	return ts.makeRequest(t, "DELETE", urlPath, map[string]any{}, useAuthHeader, accessToken)
}

// extractActivationTokenFromString is a helper function to extract activation token from email
func extractActivationTokenFromString(email *smtpmock.Message) string {
	capturedToken := tokenRegex.FindString(email.MsgRequest())
	token := strings.ReplaceAll(capturedToken, "--------------------------\r\n", "")

	return strings.ReplaceAll(token, "\r\n--------------------------", "")
}

// createUser is a helper function used to create a user
func createUser(t *testing.T, ts *testServer, name, email, password string) data.User {
	body := map[string]any{}
	body["name"] = name
	body["email"] = email
	body["password"] = password

	_, _, resBody := ts.post(t, "/auth/register", body, false, "")

	var jsonRes struct {
		User data.User
	}

	err := json.Unmarshal(resBody, &jsonRes)
	if err != nil {
		t.Error("Failed to parse json response")
	}

	return jsonRes.User
}

// activateUser activates a user
func activateUser(t *testing.T, ts *testServer, email *smtpmock.Message) {
	// Extract activation token from email
	activationToken := extractActivationTokenFromString(email)

	// Activate user
	body := map[string]any{}
	body["token"] = activationToken

	ts.put(t, "/auth/users/activate", body, false, "")
}

// createActivatedUser is a helper function to create an activated user
func createActivatedUser(t *testing.T, ts *testServer, mockMailServer *smtpmock.Server, name, email, password string) data.User {
	// Create user
	user := createUser(t, ts, name, email, password)

	// Activate user
	time.Sleep(1 * time.Second)
	activateUser(t, ts, mockMailServer.Messages()[0])

	return user
}

// loginUser is a helper function to log in an user
func loginUser(t *testing.T, ts *testServer, email, password string) string {
	body := map[string]any{}
	body["email"] = email
	body["password"] = password

	_, _, resBody := ts.post(t, "/auth/login", body, false, "")

	var jsonRes map[string]string

	err := json.Unmarshal(resBody, &jsonRes)
	if err != nil {
		t.Error("Failed to parse json response")
	}

	return jsonRes["access_token"]
}

// fetchUser retrieves a user with the given id
func fetchUser(t *testing.T, usersRepository *data.UsersRepository, userID int64) *data.User {
	// Check if users are already in the database
	fetchedUser, err := usersRepository.GetByID(context.Background(), userID)
	if err != nil {
		if !errors.Is(err, database.ErrRecordNotFound) {
			t.Fatal(err)
		}
	}

	return fetchedUser
}

// seedUsers inserts some users into the database
func seedUsers(t *testing.T, usersRepository *data.UsersRepository, permissionsRepository *data.PermissionsRepository) {
	// Check if users are already in the database
	fetchedUsers, _, err := usersRepository.GetAll(context.Background(), "", filters.Filters{Page: 1, PageSize: 20, Sort: "id", SortSafelist: []string{"id"}})
	if err != nil {
		t.Fatal(err)
	}

	// Users are already in the database
	if len(fetchedUsers) == 3 {
		return
	}

	user1 := &data.User{Name: "John Doe", Email: "john@doe.com", Gil: 100, Activated: true}
	err = user1.Password.Set("password")
	if err != nil {
		t.Fatal(err)
	}

	user2 := &data.User{Name: "Jane Doe", Email: "jane@doe.com", Gil: 100, Activated: true}
	err = user2.Password.Set("password")
	if err != nil {
		t.Fatal(err)
	}

	user3 := &data.User{Name: "Mike Doe", Email: "mike@doe.com", Gil: 100, Activated: true}
	err = user3.Password.Set("password")
	if err != nil {
		t.Fatal(err)
	}

	users := []*data.User{
		user1,
		user2,
		user3,
	}

	for i := range users {
		err := usersRepository.Insert(context.Background(), users[i], nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	err = permissionsRepository.AddForUser(context.Background(), 1, nil, "identity:read", "identity:write")
	if err != nil {
		t.Fatal(err)
	}

	err = permissionsRepository.AddForUser(context.Background(), 2, nil, "identity:read")
	if err != nil {
		t.Fatal(err)
	}
}
