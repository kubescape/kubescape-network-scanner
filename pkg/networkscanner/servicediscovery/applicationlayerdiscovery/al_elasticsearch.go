package applicationlayerdiscovery

import (
	"fmt"

	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/servicediscovery"

	"github.com/elastic/go-elasticsearch/v8"
)

type ElasticsearchDiscoveryResult struct {
	isDetected      bool
	properties      map[string]interface{}
	isAuthenticated bool
}

func (r *ElasticsearchDiscoveryResult) Protocol() string {
	return "elasticsearch"
}

func (r *ElasticsearchDiscoveryResult) GetIsDetected() bool {
	return r.isDetected
}

func (r *ElasticsearchDiscoveryResult) GetProperties() map[string]interface{} {
	return r.properties
}

func (r *ElasticsearchDiscoveryResult) GetIsAuthRequired() bool {
	return r.isAuthenticated
}

type ElasticsearchDiscovery struct {
}

func (d *ElasticsearchDiscovery) Protocol() string {
	return "elasticsearch"
}

func (d *ElasticsearchDiscovery) Discover(sessionHandler servicediscovery.ISessionHandler, presentationLayerDiscoveryResult servicediscovery.IPresentationDiscoveryResult) (servicediscovery.IApplicationDiscoveryResult, error) {
	url := fmt.Sprintf("http://%s:%d", sessionHandler.GetHost(), sessionHandler.GetPort())
	client, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{url},
	})
	if err != nil {
		return &ElasticsearchDiscoveryResult{
			isDetected:      false,
			isAuthenticated: true,
			properties:      nil,
		}, err
	}

	// Attempt to get cluster info.
	res, err := client.Info()
	if err != nil {
		return &ElasticsearchDiscoveryResult{
			isDetected:      false,
			isAuthenticated: true,
			properties:      nil,
		}, err
	}
	defer res.Body.Close()

	// Check response status
	if res.IsError() {
		return &ElasticsearchDiscoveryResult{
			isDetected:      false,
			isAuthenticated: true,
			properties:      nil,
		}, err
	}

	result := &ElasticsearchDiscoveryResult{
		isDetected:      true,
		isAuthenticated: false,
		properties:      nil,
	}
	return result, nil
}
