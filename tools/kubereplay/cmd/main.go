/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kubereplay",
	Short: "EKS audit log replay tool for Karpenter testing",
	Long: `kubereplay captures workload events from EKS audit logs
and replays them against a Karpenter cluster to test provisioning behavior.

Usage:
  kubereplay capture  -o events.json          # capture audit log events
  kubereplay snapshot --from-velero b.tar.gz  # extract Velero backup as baseline
  kubereplay merge    --snapshot s.json \
                      --events e.json         # combine baseline + events
  kubereplay replay   -f full-replay.json     # replay on cluster`,
}

func main() {
	rootCmd.AddCommand(captureCmd)
	rootCmd.AddCommand(replayCmd)
	rootCmd.AddCommand(demoCmd)
	rootCmd.AddCommand(snapshotCmd)
	rootCmd.AddCommand(mergeCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
