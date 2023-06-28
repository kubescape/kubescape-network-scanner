package applicationlayerdiscovery

import (
	"fmt"
	"net/http"

	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
)

type KubeApiServerDiscoveryResult struct {
	isDetected     bool
	properties     map[string]interface{}
	isAuthRequired bool
}

func (r *KubeApiServerDiscoveryResult) Protocol() string {
	return "Kubernetes API server"
}

func (r *KubeApiServerDiscoveryResult) GetIsDetected() bool {
	return r.isDetected
}

func (r *KubeApiServerDiscoveryResult) GetProperties() map[string]interface{} {
	return r.properties
}

func (r *KubeApiServerDiscoveryResult) GetIsAuthRequired() bool {
	return r.isAuthRequired
}

type KubeApiServerDiscovery struct {
}

func (d *KubeApiServerDiscovery) Protocol() string {
	return "Kubernetes API server"
}

func (d *KubeApiServerDiscovery) Discover(sessionHandler servicediscovery.ISessionHandler, presentationLayerDiscoveryResult servicediscovery.IPresentationDiscoveryResult) (servicediscovery.IApplicationDiscoveryResult, error) {

	url := fmt.Sprintf("http://%s:%d/api", sessionHandler.GetHost(), sessionHandler.GetPort())
	// Send a GET request to the Kubernetes API server
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Kubernetes API server: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode == http.StatusOK {
		// Kubernetes API server is detected
		result := &KubeApiServerDiscoveryResult{
			isDetected:     true,
			isAuthRequired: false,
			properties: map[string]interface{}{
				"url": url,
			},
		}
		return result, nil
	}

	// If we are able to detect the kubernetes api server but it is authenticated
	result := &KubeApiServerDiscoveryResult{
		isDetected:     true,
		isAuthRequired: true,
		properties:     nil,
	}
	return result, nil
}
