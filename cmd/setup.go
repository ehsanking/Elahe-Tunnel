package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup [internal | external]",
	Short: "Setup the server as an internal or external node.",
	Long:  `Use 'setup' to configure the current machine as either an internal (relay) node inside a censored network or an external (exit) node with free internet access.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		setupType := args[0]
		switch setupType {
		case "internal":
			fmt.Println("Setting up as an internal (Iran) server...")
			// TODO: Implement internal server setup logic
		case "external":
			fmt.Println("Setting up as an external (foreign) server...")
			// TODO: Implement external server setup logic
		default:
			fmt.Printf("Error: Invalid setup type '%s'. Please use 'internal' or 'external'.\n", setupType)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
}
