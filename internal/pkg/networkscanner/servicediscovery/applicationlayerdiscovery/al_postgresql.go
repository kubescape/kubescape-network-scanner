package applicationlayerdiscovery

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
)

type PostgresDiscoveryResult struct {
	isDetected bool
	properties map[string]interface{}
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
	// TO-DO
	return false
}

type PostgresDiscovery struct {
}

func (d *PostgresDiscovery) Protocol() string {
	return "postgresql"
}

func (d *PostgresDiscovery) Discover(sessionHandler servicediscovery.ISessionHandler, presentationLayerDiscoveryResult servicediscovery.IPresentationDiscoveryResult) (servicediscovery.IApplicationDiscoveryResult, error) {
	db, err := sql.Open("postgres", fmt.Sprintf("host=%s port=%d", sessionHandler.GetHost(), sessionHandler.GetPort()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL server: %v", err)
	}
	defer db.Close()

	// Use the connection to query the PostgreSQL server for its version
	var version string
	err = db.QueryRow("SELECT version()").Scan(&version)
	if err != nil {
		return nil, fmt.Errorf("failed to query PostgreSQL server: %v", err)
	}

	// Check if the PostgreSQL server is running and return a discovery result
	if strings.Contains(version, "PostgreSQL") {
		return &PostgresDiscoveryResult{
			isDetected: true,
			properties: map[string]interface{}{
				"version": version,
			},
		}, nil
	} else {
		return nil, nil
	}
}
