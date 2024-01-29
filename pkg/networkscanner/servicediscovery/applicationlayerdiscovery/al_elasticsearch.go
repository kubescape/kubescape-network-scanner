package applicationlayerdiscovery

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/servicediscovery"
)

// TODO: Fix this scanner
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
	response, err := http.Get(url)
	if err != nil {
		// If there is an error connecting to Elasticsearch, return a result with isDetected set to false
		result := &ElasticsearchDiscoveryResult{
			isDetected:      false,
			isAuthenticated: true,
			properties:      nil,
		}
		return result, err
	}
	defer response.Body.Close()

	// Check the response status code
	if response.StatusCode == http.StatusOK {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}

		// If the response body contains the Elasticsearch version, return a result with isDetected set to true
		if strings.Contains(string(body), "version") {
			result := &ElasticsearchDiscoveryResult{
				isDetected:      true,
				isAuthenticated: false, // Set to true if authentication is required
				properties:      make(map[string]interface{}),
			}

			// Parse the relevant data from the response body
			result.properties["name"] = getValueFromBody(body, "name")
			result.properties["cluster_name"] = getValueFromBody(body, "cluster_name")
			result.properties["cluster_uuid"] = getValueFromBody(body, "cluster_uuid")
			result.properties["version"] = getValueFromBody(body, "version.number")

			return result, nil
		}
	}

	// If the response status code is not OK (200), return a result with isDetected set to false
	result := &ElasticsearchDiscoveryResult{
		isDetected:      false,
		isAuthenticated: false,
		properties:      nil,
	}
	return result, nil
}

func getValueFromBody(body []byte, key string) string {
	// Convert body to string
	bodyStr := string(body)

	// Find the key in the body string
	startIndex := strings.Index(bodyStr, "\""+key+"\" : ")
	if startIndex == -1 {
		return ""
	}
	startIndex += len(key) + 5

	endIndex := strings.Index(bodyStr[startIndex:], "\n")
	if endIndex == -1 {
		return ""
	}

	// Return the value
	return strings.TrimSpace(bodyStr[startIndex : startIndex+endIndex])
}
