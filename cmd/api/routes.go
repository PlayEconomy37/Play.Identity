package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/riandyrn/otelchi"
)

// routes defines all the routes and hanlders in our application
func (app *Application) routes() http.Handler {
	router := chi.NewRouter()

	router.NotFound(http.HandlerFunc(app.NotFoundResponse))
	router.MethodNotAllowed(http.HandlerFunc(app.MethodNotAllowedResponse))

	router.Use(app.RecoverPanic)
	// router.Use(app.HTTPMetrics(app.Config.ServiceName))
	router.Use(otelchi.Middleware(app.Config.ServiceName, otelchi.WithChiRoutes(router)))
	router.Use(app.LogRequest)
	router.Use(app.SecureHeaders)

	router.Get("/healthcheck", app.healthCheckHandler)

	router.Post("/auth/register", app.registerUserHandler)
	router.Post("/auth/login", app.loginHandler)
	router.Post("/auth/tokens/activation", app.createActivationTokenHandler)
	router.Put("/auth/users/activate", app.activateUserHandler)

	router.Route("/users", func(r chi.Router) {
		r.Use(Authenticate(app))

		r.With(RequirePermission(app, "identity:read")).Get("/", app.getUsersHandler)
		r.With(RequirePermission(app, "identity:read")).Get("/{id}", app.getUserHandler)
		r.With(RequirePermission(app, "identity:write")).Put("/{id}", app.updateUserHandler)
		r.With(RequirePermission(app, "identity:write")).Delete("/{id}", app.deleteUserHandler)
	})

	router.Get("/metrics", promhttp.Handler().ServeHTTP)

	return router
}
