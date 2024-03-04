package applicationlayerdiscovery

import (
	"fmt"
	"time"

	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/servicediscovery"
	"github.com/streadway/amqp"
)

const (
	RabbitMQProtocolName = "rabbitmq"
)

type RabbitMQDiscoveryResult struct {
	isDetected      bool
	properties      map[string]interface{}
	isAuthenticated bool
}

func (r *RabbitMQDiscoveryResult) Protocol() string {
	return RabbitMQProtocolName
}

func (r *RabbitMQDiscoveryResult) GetIsDetected() bool {
	return r.isDetected
}

func (r *RabbitMQDiscoveryResult) GetProperties() map[string]interface{} {
	return r.properties
}

func (r *RabbitMQDiscoveryResult) GetIsAuthRequired() bool {
	return r.isAuthenticated
}

type RabbitMQDiscovery struct {
}

func (d *RabbitMQDiscovery) Protocol() string {
	return RabbitMQProtocolName
}

func (d *RabbitMQDiscovery) Discover(sessionHandler servicediscovery.ISessionHandler, presentationLayerDiscoveryResult servicediscovery.IPresentationDiscoveryResult) (servicediscovery.IApplicationDiscoveryResult, error) {
	connectionString := fmt.Sprintf("amqp://%s:%d", sessionHandler.GetHost(), sessionHandler.GetPort())
	config := amqp.Config{
		Dial: amqp.DefaultDial(time.Millisecond * 500),
	}
	conn, err := amqp.DialConfig(connectionString, config)
	if err != nil {
		return &RabbitMQDiscoveryResult{
			isDetected:      false,
			isAuthenticated: true,
			properties:      nil, // Set properties to nil as it's not used in this case
		}, err
	}
	defer conn.Close()

	// Check if the connection is authenticated
	isAuthenticated := true
	if !conn.IsClosed() {
		isAuthenticated = false
	}

	// Create RabbitMQ discovery result
	return &RabbitMQDiscoveryResult{
		isDetected:      true,
		isAuthenticated: isAuthenticated,
		properties:      nil, // Set properties to nil as it's not used in this case
	}, nil
}
