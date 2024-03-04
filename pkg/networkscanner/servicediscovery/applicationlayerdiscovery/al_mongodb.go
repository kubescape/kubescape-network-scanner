package applicationlayerdiscovery

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/kubescape/kubescape-network-scanner/pkg/networkscanner/servicediscovery"
)

type MongoDBDiscoveryResult struct {
	isDetected      bool
	properties      map[string]interface{}
	isAuthenticated bool
}

func (r *MongoDBDiscoveryResult) Protocol() string {
	return "mongodb"
}

func (r *MongoDBDiscoveryResult) GetIsDetected() bool {
	return r.isDetected
}

func (r *MongoDBDiscoveryResult) GetProperties() map[string]interface{} {
	return r.properties
}

func (r *MongoDBDiscoveryResult) GetIsAuthRequired() bool {
	return r.isAuthenticated
}

type MongoDBDiscovery struct {
}

func (d *MongoDBDiscovery) Protocol() string {
	return "mongodb"
}

func (d *MongoDBDiscovery) Discover(sessionHandler servicediscovery.ISessionHandler, presentationLayerDiscoveryResult servicediscovery.IPresentationDiscoveryResult) (servicediscovery.IApplicationDiscoveryResult, error) {
	clientOptions := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s:%d", sessionHandler.GetHost(), sessionHandler.GetPort()))
	connectionTimeout := 500 * time.Millisecond
	clientOptions.Timeout = &connectionTimeout
	ctx := context.Background()
	client, err := mongo.Connect(ctx, clientOptions)
	defer client.Disconnect(ctx)
	if err != nil {
		return &MongoDBDiscoveryResult{
			isDetected:      false,
			isAuthenticated: true,
			properties:      nil, // Set properties to nil as it's not used in this case
		}, nil
	}

	// Here: we know it is MongoDB, but we don't know if it's authenticated or not.
	result := &MongoDBDiscoveryResult{
		isDetected:      true,
		isAuthenticated: true,
		properties:      nil, // Set properties to nil as it's not used in this case
	}

	// Test the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		return result, err
	}

	// Get MongoDB server version
	serverStatusCmd := bson.D{{Key: "serverStatus", Value: 1}, {Key: "recordStats", Value: 0}}
	serverStatusResult := client.Database("admin").RunCommand(ctx, serverStatusCmd)
	if serverStatusResult.Err() == nil {
		var resultDoc bson.D
		err = serverStatusResult.Decode(&resultDoc)
		if err == nil {
			bsonBytes, _ := bson.MarshalExtJSON(resultDoc, false, false)
			var resultDocMap map[string]interface{}
			err = bson.UnmarshalExtJSON(bsonBytes, false, &resultDocMap)
			if err == nil {
				version := resultDocMap["version"].(string)
				host := resultDocMap["host"].(string)
				result.properties = map[string]interface{}{
					"version": version,
					"host":    host,
				}
			} else {
				log.Debugf("failed to decode server status result: %v", err)
			}
			result.isAuthenticated = false
		} else {
			log.Debugf("failed to decode server status result: %v", err)
		}
	} else {
		log.Debugf("failed to get server status: %v", serverStatusResult.Err())
	}

	return result, nil
}
