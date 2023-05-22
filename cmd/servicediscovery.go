package cmd

import (
	"fmt"
	"io"

	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery"
	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery/applicationlayerdiscovery"
	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery/presentationlayerdiscovery"
	"github.com/kubescape/kubescape-network-scanner/internal/pkg/networkscanner/servicediscovery/sessionlayerdiscovery"
)

type DiscoveryResult struct {
	SessionLayer      string
	PresentationLayer string
	ApplicationLayer  string
	isAuthenticated   bool
}

func ScanTargets(host string, port int) (result DiscoveryResult, err error) {
	// Discover session layer protocols
	for _, sessionDiscoveryItem := range sessionlayerdiscovery.SessionDiscoveryList {
		if sessionDiscoveryItem.Reqirement == string(servicediscovery.TCP) {
			sessionDiscoveryResult, err := sessionDiscoveryItem.Discovery.SessionLayerDiscover(host, port)
			if err != nil {
				if err != io.EOF {
					fmt.Println("Error while discovering session layer protocol:", err)
				}
				continue
			}

			if sessionDiscoveryResult.GetIsDetected() {
				result.SessionLayer = fmt.Sprintf("%v", sessionDiscoveryResult.Protocol())
				// Connect to session handler
				sessionHandler, err := sessionDiscoveryResult.GetSessionHandler()
				if err != nil {
					if err != io.EOF {
						fmt.Println("Error while discovering session layer protocol:", err)
					}
					continue
				}

				// Discover presentation layer protocols
				presentationLayerDetected := false
				for _, presentationDiscoveryItem := range presentationlayerdiscovery.PresentationDiscoveryList {
					if presentationDiscoveryItem.Reqirement == string(servicediscovery.TCP) {
						presentationDiscoveryResult, err := presentationDiscoveryItem.Discovery.Discover(sessionHandler)
						if err != nil {
							if err != io.EOF {
								fmt.Println("Error while discovering session layer protocol:", err)
							}
							continue
						}

						if presentationDiscoveryResult.GetIsDetected() {
							presentationLayerDetected = true
							result.PresentationLayer = fmt.Sprintf("%v", presentationDiscoveryResult.Protocol())

							// Discover application layer protocols
							for _, applicationDiscoveryItem := range applicationlayerdiscovery.ApplicationDiscoveryList {
								if applicationDiscoveryItem.Reqirement == string(servicediscovery.TCP) {
									applicationDiscoveryResult, err := applicationDiscoveryItem.Discovery.Discover(sessionHandler, presentationDiscoveryResult)
									if err != nil {
										if err != io.EOF {
											fmt.Println("Error while discovering application layer protocol:", err)
										}
										continue
									}

									if applicationDiscoveryResult.GetIsDetected() {
										result.ApplicationLayer = fmt.Sprintf("%v", applicationDiscoveryResult.Protocol())
										result.isAuthenticated = applicationDiscoveryResult.GetIsAuthRequired()
									} else {
										fmt.Println("No application layer protocol detected")
									}
								}
							}

							break // Stop checking presentation layer protocols
						}
					}
				}

				if !presentationLayerDetected {

					// Continue to discover application layer protocols
					for _, applicationDiscoveryItem := range applicationlayerdiscovery.ApplicationDiscoveryList {
						if applicationDiscoveryItem.Reqirement == string(servicediscovery.TCP) {
							applicationDiscoveryResult, err := applicationDiscoveryItem.Discovery.Discover(sessionHandler, nil)
							if err != nil {
								if err != io.EOF {
									fmt.Println("Error while discovering application layer protocol:", err)
								}
								continue
							}

							if applicationDiscoveryResult.GetIsDetected() {
								result.ApplicationLayer = fmt.Sprintf("%v", applicationDiscoveryResult.Protocol())
								result.isAuthenticated = applicationDiscoveryResult.GetIsAuthRequired()

							} else {
								fmt.Println("No application layer protocol detected")
							}
						}
					}
				}

			} else {
				fmt.Println("No session layer protocol detected")
			}

			// If session layer protocol not TCP, continue to the next session layer protocol
			continue
		}

		// If session layer protocol not TCP, continue to the next session layer protocol
		continue
	}
	return result, nil
}
