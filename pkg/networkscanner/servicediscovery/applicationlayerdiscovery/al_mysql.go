package applicationlayerdiscovery

import (
	"fmt"
	"strings"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

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
	dataSourceName := fmt.Sprintf("root:@tcp(%s:%d)/", sessionHandler.GetHost(), sessionHandler.GetPort())

	// Attempt to open a connection
	db, err := gorm.Open(mysql.Open(dataSourceName), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		if strings.Contains(err.Error(), "Access denied for user") {
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
	sqlDB, err := db.DB()
	if err != nil {
		return &MysqlDiscoveryResult{
			IsDetected:      true,
			IsAuthenticated: true,
			Properties:      nil,
		}, err
	}
	defer sqlDB.Close()

	result := &MysqlDiscoveryResult{
		IsDetected:      true,
		IsAuthenticated: false,
		Properties:      nil,
	}

	return result, nil
}
