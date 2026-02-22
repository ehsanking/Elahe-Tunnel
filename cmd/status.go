package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check the current status of the tunnel.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Checking tunnel status...")
		fmt.Println("Status: Inactive") // Placeholder
		// TODO: Implement status check logic
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
