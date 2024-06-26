package applicationlayerdiscovery

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"database/sql"

	mysqlDriver "github.com/go-sql-driver/mysql"

	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/servicediscovery"
)

type MysqlDiscoveryResult struct {
	IsDetected      bool
	IsAuthenticated bool
	Properties      map[string]interface{}
}

type MysqlDiscovery struct{}

func (r *MysqlDiscoveryResult) Protocol() string {
	return "mysql"
}

func (r *MysqlDiscoveryResult) GetIsAuthRequired() bool {
	return r.IsAuthenticated
}

func (r *MysqlDiscoveryResult) GetIsDetected() bool {
	return r.IsDetected
}

func (r *MysqlDiscoveryResult) GetProperties() map[string]interface{} {
	return r.Properties
}

func (d *MysqlDiscovery) Protocol() string {
	return "mysql"
}

func (d *MysqlDiscovery) Discover(sessionHandler servicediscovery.ISessionHandler, presentationLayerDiscoveryResult servicediscovery.IPresentationDiscoveryResult) (servicediscovery.IApplicationDiscoveryResult, error) {
	mysqlDriver.SetLogger(log.New(io.Discard, "", 0))
	dataSourceName := fmt.Sprintf("root:@tcp(%s:%d)/?timeout=3s", sessionHandler.GetHost(), sessionHandler.GetPort())

	// Attempt to open a connection
	db, err := sql.Open("mysql", dataSourceName)
	if err != nil {
		return &MysqlDiscoveryResult{
			IsDetected:      false,
			IsAuthenticated: true,
			Properties:      nil,
		}, err
	}

	// Ping the server with passed context()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = db.PingContext(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "Access denied") {
			return &MysqlDiscoveryResult{
				IsDetected:      true,
				IsAuthenticated: true,
				Properties:      nil,
			}, nil
		}
		return &MysqlDiscoveryResult{
			IsDetected:      false,
			IsAuthenticated: true,
			Properties:      nil,
		}, err
	}

	result := &MysqlDiscoveryResult{
		IsDetected:      true,
		IsAuthenticated: false,
		Properties:      nil,
	}

	return result, nil
}
