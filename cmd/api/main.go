package main

import (
	"context"
	"os"
	"time"

	"github.com/PlayEconomy37/Play.Common/common"
	"github.com/PlayEconomy37/Play.Common/configuration"
	"github.com/PlayEconomy37/Play.Common/database"
	"github.com/PlayEconomy37/Play.Common/events"
	"github.com/PlayEconomy37/Play.Common/logger"
	"github.com/PlayEconomy37/Play.Common/mailer"
	"github.com/PlayEconomy37/Play.Common/opentelemetry"
	"github.com/PlayEconomy37/Play.Identity/assets"
	"github.com/PlayEconomy37/Play.Identity/internal/constants"
	"github.com/PlayEconomy37/Play.Identity/internal/data"
	"github.com/PlayEconomy37/Play.Identity/internal/rabbitmq"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
)

// Application is a struct that defines the Identity's microservice application.
// It embeds the common packages common application struct.
type Application struct {
	common.App
	UsersRepository       *data.UsersRepository
	TokensRepository      *data.TokensRepository
	PermissionsRepository *data.PermissionsRepository
	UserUpdatedPublisher  *rabbitmq.UserUpdatedPublisher
	Mailer                mailer.Mailer
}

func main() {
	// Setup logger
	logger := logger.New(os.Stdout, logger.LevelInfo)

	// Read configuration
	config, err := configuration.LoadConfig("config/dev.json")
	if err != nil {
		logger.Fatal(err, nil)
	}

	// Start Postgres database
	db, err := database.NewPostgresDB(config, true, assets.EmbeddedFiles)
	if err != nil {
		logger.Fatal(err, nil)
	}

	defer db.Close()

	// Initialize tracer
	tracerProvider := opentelemetry.SetupTracer(false)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := tracerProvider.Shutdown(ctx); err != nil {
			logger.Error(err, nil)
		}
	}()

	// Create a new SQL stats collector
	collector := opentelemetry.NewSQLStatsCollector(constants.Database, db)

	// Register the collector with Prometheus
	prometheus.MustRegister(collector)

	// Create email server
	mailServer := mailer.New(config.SMTP.Host, config.SMTP.Port, config.SMTP.Username, config.SMTP.Password, config.SMTP.Sender)

	// Connect to RabbitMQ
	rabbitMQConnection, err := events.NewRabbitMQConnection(config)
	if err != nil {
		logger.Fatal(err, nil)
	}

	defer rabbitMQConnection.Close()

	// Create users repository
	usersRepository := data.NewUsersRepository(db)

	// Create UpdatedUserPublisher
	userUpdatedPublisher, err := rabbitmq.NewUserUpdatedPublisher(rabbitMQConnection, usersRepository)
	if err != nil {
		logger.Fatal(err, nil)
	}

	app := &Application{
		App: common.App{
			Config: config,
			Logger: logger,
			Tracer: otel.Tracer(config.ServiceName),
		},
		UsersRepository:       usersRepository,
		TokensRepository:      data.NewTokensRepository(db),
		PermissionsRepository: data.NewPermissionsRepository(db),
		UserUpdatedPublisher:  userUpdatedPublisher,
		Mailer:                mailServer,
	}

	err = app.Serve(app.routes())
	if err != nil {
		logger.Fatal(err, nil)
	}
}
