package applicationlayerdiscovery

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/servicediscovery"

	"github.com/IBM/sarama"
)

type KafkaDiscoveryResult struct {
	isDetected      bool
	properties      map[string]interface{}
	isAuthenticated bool
}

func (r *KafkaDiscoveryResult) Protocol() string {
	return "kafka"
}

func (r *KafkaDiscoveryResult) GetIsDetected() bool {
	return r.isDetected
}

func (r *KafkaDiscoveryResult) GetProperties() map[string]interface{} {
	return r.properties
}

func (r *KafkaDiscoveryResult) GetIsAuthRequired() bool {
	return r.isAuthenticated
}

type KafkaDiscovery struct {
}

func (k *KafkaDiscovery) Protocol() string {
	return "kafka"
}

func (k *KafkaDiscovery) Discover(sessionHandler servicediscovery.ISessionHandler, presentationLayerDiscoveryResult servicediscovery.IPresentationDiscoveryResult) (servicediscovery.IApplicationDiscoveryResult, error) {
	// Set the Kafka broker addresses
	brokerList := []string{fmt.Sprintf("%s:%d", sessionHandler.GetHost(), sessionHandler.GetPort())}

	// Configure the producer
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 1
	config.Producer.Timeout = 3
	config.Producer.Return.Successes = true

	// Create a new SyncProducer
	producer, err := sarama.NewSyncProducer(brokerList, config)
	if err != nil {
		return &KafkaDiscoveryResult{
			isDetected:      false,
			isAuthenticated: true,
			properties:      nil, // Set properties to nil as it's not used in this case
		}, nil
	}
	defer func() {
		if err := producer.Close(); err != nil {
			log.Debugf("Failed to close Kafka producer: %s", err)
		}
	}()

	// Create Kafka discovery result
	return &KafkaDiscoveryResult{
		isDetected:      true,
		isAuthenticated: false,
		properties:      nil, // Set properties to nil as it's not used in this case
	}, nil
}
