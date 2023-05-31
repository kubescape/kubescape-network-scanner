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

const numGoroutines = 8

func ScanTargets(host string, port int) (result DiscoveryResult, err error) {
	sessionLayerChan := make(chan string)
	presentationLayerChan := make(chan string)
	applicationLayerChan := make(chan DiscoveryResult)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, numGoroutines)

	// Discover session layer protocols
	wg.Add(1)
	go func() {
		defer wg.Done()
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
					sessionLayer := fmt.Sprintf("%v", sessionDiscoveryResult.Protocol())
					sessionLayerChan <- sessionLayer
					// Connect to session handler
					sessionHandler, err := sessionDiscoveryResult.GetSessionHandler()
					if err != nil {
						if err != io.EOF {
							fmt.Println("Error while discovering session layer protocol:", err)
						}
						continue
					}

					wg.Add(1)
					semaphore <- struct{}{}
					go func(sessionHandler servicediscovery.ISessionHandler) {
						defer func() {
							<-semaphore
							wg.Done()
						}()

						// Discover presentation layer protocols
						presentationLayerDetected := false
						for _, presentationDiscoveryItem := range presentationlayerdiscovery.PresentationDiscoveryList {
							if presentationDiscoveryItem.Reqirement == string(servicediscovery.TCP) {
								presentationDiscoveryResult, err := presentationDiscoveryItem.Discovery.Discover(sessionHandler)
								if err != nil {
									if err != io.EOF {
										fmt.Println("Error while discovering session layer protocol:", err)
										continue
									}
								}

								if presentationDiscoveryResult.GetIsDetected() {
									presentationLayerDetected = true
									result.PresentationLayer = fmt.Sprintf("%v", presentationDiscoveryResult.Protocol())

									wg.Add(1)
									semaphore <- struct{}{}
									go func(presentationDiscoveryResult servicediscovery.IPresentationDiscoveryResult) {
										defer func() {
											<-semaphore
											wg.Done()
										}()

										// Discover application layer protocols
										for _, applicationDiscoveryItem := range applicationlayerdiscovery.ApplicationDiscoveryList {
											if applicationDiscoveryItem.Reqirement == string(servicediscovery.TCP) {
												applicationDiscoveryResult, err := applicationDiscoveryItem.Discovery.Discover(sessionHandler, presentationDiscoveryResult)
												if err != nil {
													if err != io.EOF {
														fmt.Println("Error while discovering application layer protocol:", err)
														continue
													}
												}

												if applicationDiscoveryResult.GetIsDetected() {
													result.ApplicationLayer = fmt.Sprintf("%v", applicationDiscoveryResult.Protocol())
													result.isAuthenticated = applicationDiscoveryResult.GetIsAuthRequired()
												} else {
													fmt.Println("No application layer protocol detected")
												}
											}
										}

										applicationLayerChan <- result
									}(presentationDiscoveryResult)

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
											continue
										}
									}

									if applicationDiscoveryResult.GetIsDetected() {
										result.ApplicationLayer = fmt.Sprintf("%v", applicationDiscoveryResult.Protocol())
										result.isAuthenticated = applicationDiscoveryResult.GetIsAuthRequired()
									} else {
										fmt.Println("No application layer protocol detected")
									}
								}
							}
							applicationLayerChan <- result
						}

						presentationLayerChan <- result.PresentationLayer
					}(sessionHandler)

					break // Stop checking session layer protocols
				}
			}
		}
		close(presentationLayerChan)
		close(applicationLayerChan)
	}()

	go func() {
		wg.Wait()
		close(sessionLayerChan)
	}()

	result.SessionLayer = <-sessionLayerChan

	// Wait for presentation layer result
	for presentationLayer := range presentationLayerChan {
		if presentationLayer != "" {
			result.PresentationLayer = presentationLayer
			break
		}
	}

	// Wait for application layer result
	appResult := <-applicationLayerChan
	if appResult.ApplicationLayer != "" {
		result = appResult
	}

	return result, nil
}
