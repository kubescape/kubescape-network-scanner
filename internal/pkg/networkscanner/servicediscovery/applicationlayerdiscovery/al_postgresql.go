package applicationlayerdiscovery

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"

	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
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
	db, err := sql.Open("postgres", fmt.Sprintf("host=%s port=%d sslmode=disable", sessionHandler.GetHost(), sessionHandler.GetPort()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL server: %v", err)
	}
	defer db.Close()

	// Here: we know it is postgresql, but we don't know if it is authenticated or not
	result := &PostgresDiscoveryResult{
		isDetected:      true,
		isAuthenticated: true,
		properties:      nil, // Set properties to nil as it's not used in this case
	}

	// Use the connection to query the PostgreSQL server for its version
	var version string
	err = db.QueryRow("SELECT version()").Scan(&version)
	if err != nil {
		return result, nil
	} else {
		result.isAuthenticated = false
		result.properties = map[string]interface{}{
			"version": version,
		}
		return result, nil
	}

}
