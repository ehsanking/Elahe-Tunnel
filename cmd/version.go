package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Search Tunnel",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := os.ReadFile("VERSION")
		if err != nil {
			fmt.Println("Error reading version file: ", err)
			os.Exit(1)
		}
		fmt.Printf("search-tunnel version %s\n", string(data))
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
