package cmd

import (
	"fmt"

	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery/applicationlayerdiscovery"
	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery/presentationlayerdiscovery"
	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery/sessionlayerdiscovery"
)

type DiscoveryResult struct {
	SessionLayer      string
	PresentationLayer string
	ApplicationLayer  string
}

func ScanTargets(host string, port int) (result DiscoveryResult, err error) {
	// Discover session layer protocols
	for _, sessionDiscoveryItem := range sessionlayerdiscovery.SessionDiscoveryList {
		if sessionDiscoveryItem.Reqirement == string(servicediscovery.TCP) {
			sessionDiscoveryResult, err := sessionDiscoveryItem.Discovery.SessionLayerDiscover(host, port)
			if err != nil {
				fmt.Println("Error while discovering session layer protocol:", err)
				continue
			}

			if sessionDiscoveryResult.GetIsDetected() {
				result.SessionLayer = fmt.Sprintf("%v", sessionDiscoveryResult.Protocol())

				// Connect to session handler
				sessionHandler, err := sessionDiscoveryResult.GetSessionHandler()
				if err != nil {
					fmt.Println("Error while creating session handler:", err)
					continue
				}

				// Discover presentation layer protocols
				for _, presentationDiscoveryItem := range presentationlayerdiscovery.PresentationDiscoveryList {
					if presentationDiscoveryItem.Reqirement == string(servicediscovery.TCP) {
						presentationDiscoveryResult, err := presentationDiscoveryItem.Discovery.Discover(sessionHandler)
						if err != nil {
							fmt.Println("Error while discovering presentation layer protocol:", err)
							continue
						}

						if presentationDiscoveryResult.GetIsDetected() {
							result.PresentationLayer = fmt.Sprintf("%v", presentationDiscoveryResult.Protocol())
							// Discover application layer protocols
							for _, applicationDiscoveryItem := range applicationlayerdiscovery.ApplicationDiscoveryList {
								if applicationDiscoveryItem.Reqirement == string(servicediscovery.TCP) {
									applicationDiscoveryResult, err := applicationDiscoveryItem.Discovery.Discover(sessionHandler, presentationDiscoveryResult)
									if err != nil {
										fmt.Println("Error while discovering application layer protocol:", err)
										continue
									}

									if applicationDiscoveryResult.GetIsDetected() {
										result.ApplicationLayer = applicationDiscoveryResult.Protocol()
									}
								}
							}
						}
					}
				}
				// break after finding the first detected session layer protocol
				break
			}
		}
	}
	return result, nil
}
