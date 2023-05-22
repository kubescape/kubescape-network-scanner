package applicationlayerdiscovery

import (
	"database/sql"
	"fmt"
	"strings"

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
	db, err := sql.Open("postgres", fmt.Sprintf("host=%s port=%d sslmode=disable user= password= ", sessionHandler.GetHost(), sessionHandler.GetPort()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL server: %v", err)
	}
	defer db.Close()

	// Use the connection to query the PostgreSQL server for its version
	var version string
	err = db.QueryRow("SELECT version()").Scan(&version)
	if err != nil {
		// Check if the error message contains "postgresql" and set isDetected to true
		if strings.Contains(err.Error(), "pg_hba.conf") {
			return &PostgresDiscoveryResult{
				isDetected:      true,
				isAuthenticated: true,
				properties:      nil, // Set properties to nil as it's not used in this case
			}, nil
		}
		return nil, fmt.Errorf("failed to query PostgreSQL server: %v", err)
	}

	// Check if the PostgreSQL server is running and return a discovery result
	if strings.Contains(version, "PostgreSQL") {
		return &PostgresDiscoveryResult{
			isDetected:      true,
			isAuthenticated: false,
			properties: map[string]interface{}{
				"version": version,
			},
		}, nil
	} else {
		return nil, nil
	}
}
