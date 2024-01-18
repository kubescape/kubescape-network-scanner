package applicationlayerdiscovery

import (
	"fmt"

	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
	"github.com/streadway/amqp"
)

const (
	RabbitMQProtocolName = "rabbitmq"
	DefaultUserName      = "guest"
	DefaultPassword      = "guest"
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
	conn, err := amqp.Dial(fmt.Sprintf("amqp://%s:%s@%s:%d", DefaultUserName, DefaultPassword, sessionHandler.GetHost(), sessionHandler.GetPort()))
	if err != nil {
		// If there is an error connecting to RabbitMQ
		result := &RabbitMQDiscoveryResult{
			isDetected:      false,
			isAuthenticated: false,
			properties:      nil,
		}
		return result, nil
	}
	defer conn.Close()

	// Check if the connection is authenticated
	isAuthenticated := false
	if !conn.IsClosed() {
		isAuthenticated = true
	}

	// Create RabbitMQ discovery result
	return &RabbitMQDiscoveryResult{
		isDetected:      true,
		isAuthenticated: isAuthenticated,
		properties:      nil, // Set properties to nil as it's not used in this case
	}, nil
}
