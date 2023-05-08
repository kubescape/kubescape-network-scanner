package servicediscovery

import (
	"fmt"
)

type DiscoveryResult struct {
	SessionLayer      string
	PresentationLayer string
	ApplicationLayer  string
}

func ScanTargets(host string, port int) (result DiscoveryResult, err error) {
	// Discover session layer protocols
	for _, sessionDiscoveryItem := range SessionDiscoveryList {
		if sessionDiscoveryItem.Reqirement == string(TCP) {
			sessionDiscoveryResult, err := sessionDiscoveryItem.Discovery.SessionLayerDiscover(host, port)
			if err != nil {
				fmt.Println("Error while discovering session layer protocol:", err)
				continue
			}

			if sessionDiscoveryResult.GetIsDetected() {
				result.SessionLayer = sessionDiscoveryResult.Protocol()

				// Connect to session handler
				sessionHandler, err := sessionDiscoveryResult.GetSessionHandler()
				if err != nil {
					fmt.Println("Error while creating session handler:", err)
					continue
				}

				// Discover presentation layer protocols
				for _, presentationDiscoveryItem := range PresentationDiscoveryList {
					if presentationDiscoveryItem.Reqirement == string(TCP) {
						presentationDiscoveryResult, err := presentationDiscoveryItem.Discovery.Discover(sessionHandler)
						if err != nil {
							fmt.Println("Error while discovering presentation layer protocol:", err)
							continue
						}

						if presentationDiscoveryResult.GetIsDetected() {
							result.PresentationLayer = presentationDiscoveryResult.Protocol()
							// Discover application layer protocols
							for _, applicationDiscoveryItem := range ApplicationDiscoveryList {
								if applicationDiscoveryItem.Reqirement == string(TCP) {
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
