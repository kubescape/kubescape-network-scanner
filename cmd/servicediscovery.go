package cmd

import (
	"fmt"
	"io"
	"sync"

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
	var sessionWg sync.WaitGroup
	var presentationWg sync.WaitGroup
	var applicationWg sync.WaitGroup

	// Discover session layer protocols concurrently
	sessionLayerChan := make(chan sessionLayerDiscoveryResult)
	for _, sessionDiscoveryItem := range sessionlayerdiscovery.SessionDiscoveryList {
		if sessionDiscoveryItem.Reqirement == string(servicediscovery.TCP) {
			sessionWg.Add(1)
			go func(sessionDiscoveryItem sessionlayerdiscovery.SessionLayerDiscoveryListItem) {
				defer sessionWg.Done()
				sessionDiscoveryResult, err := sessionDiscoveryItem.Discovery.SessionLayerDiscover(host, port)
				if err != nil {
					if err != io.EOF {
						fmt.Println("Error while discovering session layer protocol:", err)
					}
					return
				}
				sessionLayerChan <- sessionDiscoveryResult
			}(sessionDiscoveryItem)
		}
	}

	go func() {
		sessionWg.Wait()
		close(sessionLayerChan)
	}()

	// Process session layer discovery results
	var sessionDiscoveryResult sessionLayerDiscoveryResult
	for sessionDiscoveryResult = range sessionLayerChan {
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

			// Discover presentation layer protocols concurrently
			presentationLayerChan := make(chan presentationLayerDiscoveryResult)
			for _, presentationDiscoveryItem := range presentationlayerdiscovery.PresentationDiscoveryList {
				if presentationDiscoveryItem.Reqirement == string(servicediscovery.TCP) {
					presentationWg.Add(1)
					go func(presentationDiscoveryItem presentationlayerdiscovery.PresentationLayerDiscoveryListItem) {
						defer presentationWg.Done()
						presentationDiscoveryResult, err := presentationDiscoveryItem.Discovery.Discover(sessionHandler)
						if err != nil {
							if err != io.EOF {
								fmt.Println("Error while discovering session layer protocol:", err)
							}
							return
						}
						presentationLayerChan <- presentationDiscoveryResult
					}(presentationDiscoveryItem)
				}
			}

			go func() {
				presentationWg.Wait()
				close(presentationLayerChan)
			}()

			// Process presentation layer discovery results
			var presentationDiscoveryResult presentationLayerDiscoveryResult
			for presentationDiscoveryResult = range presentationLayerChan {
				if presentationDiscoveryResult.GetIsDetected() {
					result.PresentationLayer = fmt.Sprintf("%v", presentationDiscoveryResult.Protocol())

					// Discover application layer protocols concurrently
					applicationLayerChan := make(chan applicationLayerDiscoveryResult)
					for _, applicationDiscoveryItem := range applicationlayerdiscovery.ApplicationDiscoveryList {
						if applicationDiscoveryItem.Reqirement == string(servicediscovery.TCP) {
							applicationWg.Add(1)
							go func(applicationDiscoveryItem applicationlayerdiscovery.ApplicationDiscoveryListItem) {
								defer applicationWg.Done()
								applicationDiscoveryResult, err := applicationDiscoveryItem.Discovery.Discover(sessionHandler, presentationDiscoveryResult)
								if err != nil {
									return
								}
								applicationLayerChan <- applicationDiscoveryResult
							}(applicationDiscoveryItem)
						}
					}

					go func() {
						applicationWg.Wait()
						close(applicationLayerChan)
					}()

					// Process application layer discovery results
					var applicationDiscoveryResult applicationLayerDiscoveryResult
					for applicationDiscoveryResult = range applicationLayerChan {
						if applicationDiscoveryResult.GetIsDetected() {
							result.ApplicationLayer = fmt.Sprintf("%v", applicationDiscoveryResult.Protocol())
							result.isAuthenticated = applicationDiscoveryResult.GetIsAuthRequired()
						} else {
						}
					}

					break // Stop checking presentation layer protocols
				}
			}

			if presentationDiscoveryResult == nil {
				// Continue to discover application layer protocols
				applicationLayerChan := make(chan applicationLayerDiscoveryResult)
				for _, applicationDiscoveryItem := range applicationlayerdiscovery.ApplicationDiscoveryList {
					if applicationDiscoveryItem.Reqirement == string(servicediscovery.TCP) {
						applicationWg.Add(1)
						go func(applicationDiscoveryItem applicationlayerdiscovery.ApplicationDiscoveryListItem) {
							defer applicationWg.Done()
							applicationDiscoveryResult, err := applicationDiscoveryItem.Discovery.Discover(sessionHandler, nil)
							if err != nil {
								return
							}
							applicationLayerChan <- applicationDiscoveryResult
						}(applicationDiscoveryItem)
					}
				}

				go func() {
					applicationWg.Wait()
					close(applicationLayerChan)
				}()

				// Process application layer discovery results
				var applicationDiscoveryResult applicationLayerDiscoveryResult
				for applicationDiscoveryResult = range applicationLayerChan {
					if applicationDiscoveryResult.GetIsDetected() {
						result.ApplicationLayer = fmt.Sprintf("%v", applicationDiscoveryResult.Protocol())
						result.isAuthenticated = applicationDiscoveryResult.GetIsAuthRequired()
					} else {
					}
				}
			}
		} else {
			fmt.Println("No session layer protocol detected")
		}
	}

	return result, nil
}

// Define discovery result interfaces to use channels
type sessionLayerDiscoveryResult = servicediscovery.ISessionLayerDiscoveryResult
type presentationLayerDiscoveryResult = servicediscovery.IPresentationDiscoveryResult
type applicationLayerDiscoveryResult = servicediscovery.IApplicationDiscoveryResult
