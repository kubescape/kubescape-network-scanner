package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "kubenetworkscan",
	Short:         "a cli tool for port scanning and service discovery inside kubernetes clusters",
	Long:          `Kubescape Network Scanner is a cli tool for scanning open ports and discovering services inside and outside the kubernetes clusters. It also checks if the services are authenticated or not`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
