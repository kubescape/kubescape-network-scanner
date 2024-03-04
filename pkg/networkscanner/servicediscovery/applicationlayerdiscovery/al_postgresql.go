package applicationlayerdiscovery

import (
	"database/sql"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	_ "github.com/lib/pq"

	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/servicediscovery"
)

type PostgresDiscoveryResult struct {
	isDetected      bool
	properties      map[string]interface{}
	isAuthenticated bool
}

func (r *PostgresDiscoveryResult) Protocol() string {
	return "postgresql"
}

func (r *PostgresDiscoveryResult) GetIsDetected() bool {
	return r.isDetected
}

func (r *PostgresDiscoveryResult) GetProperties() map[string]interface{} {
	return r.properties
}

func (r *PostgresDiscoveryResult) GetIsAuthRequired() bool {
	return r.isAuthenticated
}

type PostgresDiscovery struct {
}

func (d *PostgresDiscovery) Protocol() string {
	return "postgresql"
}

func (d *PostgresDiscovery) Discover(sessionHandler servicediscovery.ISessionHandler, presentationLayerDiscoveryResult servicediscovery.IPresentationDiscoveryResult) (servicediscovery.IApplicationDiscoveryResult, error) {
	// Set a timeout of 30 ms
	db, err := sql.Open("postgres", fmt.Sprintf("host=%s port=%d user=postgres sslmode=disable connect_timeout=1", sessionHandler.GetHost(), sessionHandler.GetPort()))
	if err != nil {
		log.Debugf("Error while connecting to postgresql: %s", err.Error())
		return &PostgresDiscoveryResult{
			isDetected:      false,
			isAuthenticated: true,
			properties:      nil, // Set properties to nil as it's not used in this case
		}, err
	}
	defer db.Close()

	// Here: we know it is postgresql, but we don't know if it is authenticated or not
	result := &PostgresDiscoveryResult{
		isDetected:      true,
		isAuthenticated: true,
		properties:      nil, // Set properties to nil as it's not used in this case
	}

	// Test the connection
	err = db.Ping()
	if err != nil {
		if strings.Contains(err.Error(), "authentication failed") {
			result.isDetected = true
			result.isAuthenticated = true
		} else if strings.Contains(err.Error(), "role \"admin\" does not exist") {
			// We need this case to detect that we are using an user that does not exist but still it is unauthenticated
			result.isDetected = true
			result.isAuthenticated = false
		} else {
			result.isDetected = false
			result.isAuthenticated = true
		}
	} else {
		result.isDetected = true
		result.isAuthenticated = false
	}
	return result, nil
}
