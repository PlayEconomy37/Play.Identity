package rabbitmq

import (
	"context"

	"github.com/PlayEconomy37/Play.Identity/internal/data"

	amqp "github.com/rabbitmq/amqp091-go"
)

// UserUpdatedPublisher is the publisher for user updated event
type UserUpdatedPublisher struct {
	conn            *amqp.Connection
	exchangeName    string
	routingKey      string
	UsersRepository *data.UsersRepository
}

// NewUserUpdatedPublisher returns a new UserUpdatedPublisher
func NewUserUpdatedPublisher(conn *amqp.Connection, usersRepository *data.UsersRepository) (*UserUpdatedPublisher, error) {
	publisher := UserUpdatedPublisher{
		conn:            conn,
		exchangeName:    "Play.Identity:user-updated",
		routingKey:      "",
		UsersRepository: usersRepository,
	}

	// Declare exchange, create channel and queue, and bind the two
	err := publisher.DeclareExchange()
	if err != nil {
		return nil, err
	}

	return &publisher, nil
}

// DeclareExchange declares an exchange
func (publisher *UserUpdatedPublisher) DeclareExchange() error {
	channel, err := publisher.conn.Channel()
	if err != nil {
		return err
	}

	// Declare exchange
	err = channel.ExchangeDeclare(
		publisher.exchangeName,
		"fanout", // Exchange type
		true,     // durable?
		false,    // auto-delete?
		false,    // internal exchange
		false,    // no wait?
		nil,      // arguments
	)
	if err != nil {
		return err
	}

	return nil
}

// Publish publishes a message to the linked exchange
func (publisher *UserUpdatedPublisher) Publish(ctx context.Context, body []byte) error {
	channel, err := publisher.conn.Channel()
	if err != nil {
		return err
	}

	defer channel.Close()

	// Publish message with given body
	err = channel.PublishWithContext(ctx,
		publisher.exchangeName, // exchange
		publisher.routingKey,   // routing key
		false,                  // mandatory
		false,                  // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        body,
		})
	if err != nil {
		return err
	}

	return nil
}
