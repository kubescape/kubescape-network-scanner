package applicationlayerdiscovery

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

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
	url := fmt.Sprintf("https://%s:%d/api", sessionHandler.GetHost(), sessionHandler.GetPort())

	// Create a custom transport with insecure skip verify
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Create an http.Client with the custom transport
	client := &http.Client{Transport: tr}

	// Send a GET request to the Kubernetes API server
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Kubernetes API server: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode == http.StatusOK {
		// Check if the response body contains the Kubernetes API server version
		if resp.Header.Get("kind") == "APIVersions" {
			// Kubernetes API server is detected and not authenticated
			result := &KubeApiServerDiscoveryResult{
				isDetected:     true,
				isAuthRequired: false,
				properties: map[string]interface{}{
					"url": url,
				},
			}
			return result, nil
		}
	} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Check if the response is in JSON format
		contentType := resp.Header.Get("Content-Type")
		if strings.HasPrefix(contentType, "application/json") {
			// Convert body to struct
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read response body: %v", err)
			}

			var responseJSON map[string]interface{}
			err = json.Unmarshal(body, &responseJSON)
			if err != nil {
				return nil, fmt.Errorf("failed to parse JSON response: %v", err)
			}

			kind, ok := responseJSON["kind"].(string)
			if ok && kind == "Status" {
				// Kubernetes API server is detected and authenticated
				result := &KubeApiServerDiscoveryResult{
					isDetected:     true,
					isAuthRequired: true,
					properties:     nil,
				}
				return result, nil
			}
		}
	}

	// If the response status is neither OK (200) nor Unauthorized (401), the Kubernetes API server is not detected
	result := &KubeApiServerDiscoveryResult{
		isDetected:     false,
		isAuthRequired: false,
		properties:     nil,
	}
	return result, nil
}
