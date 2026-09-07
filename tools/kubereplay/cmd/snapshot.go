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
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/aws/karpenter-provider-aws/tools/kubereplay/pkg/snapshot"
)

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Create baseline cluster state from a Velero backup archive",
	Long: `snapshot reads a Velero backup .tar.gz file and extracts the cluster state
at the time of the backup. It converts all running workloads into T+0 create
events that represent the baseline cluster load before your capture window.

Supported resource types:
  Deployments   → captured as-is
  StatefulSets  → converted to equivalent Deployments (same replicas + resources)
  DaemonSets    → converted to Deployments with --node-count replicas
  CronJobs      → active executions converted to Jobs (idle CronJobs skipped)
  Jobs          → excluded (kaas-backup excludes jobs from Velero backups)

Typical workflow (aligned to Velero 6h schedule):
  # 1. Download Velero backup matching your capture start time
  velero backup download <backup-name> --output /tmp/baseline.tar.gz

  # 2. Create snapshot (T+0 baseline)
  kubereplay snapshot --from-velero /tmp/baseline.tar.gz --output snapshot.json

  # 3. Capture 6h of events starting at same time as Velero backup
  kubereplay capture --cluster-name csp-artemis2a7 \
    --start-time 2026-09-02T06:18:00Z --duration 6h --output events.json

  # 4. Merge baseline + events
  kubereplay merge --snapshot snapshot.json --events events.json --output full.json

  # 5. Replay
  kubereplay replay -f full.json --nodepool kaas.acquia.io/kubereplay \
    --nodepool-name kubereplay --speed 6 --timeout 90m`,
	RunE: runSnapshot,
}

var (
	snapshotVeleroPath  string
	snapshotOutput      string
	snapshotTime        string
	snapshotNodeCount   int
	snapshotCluster     string
)

func init() {
	snapshotCmd.Flags().StringVar(&snapshotVeleroPath, "from-velero", "", "Path to Velero backup .tar.gz file (required)")
	snapshotCmd.Flags().StringVarP(&snapshotOutput, "output", "o", "snapshot.json", "Output snapshot file")
	snapshotCmd.Flags().StringVar(&snapshotTime, "time", "", "Snapshot timestamp in RFC3339 (default: backup file mtime). Used as T+0 for all events.")
	snapshotCmd.Flags().IntVar(&snapshotNodeCount, "node-count", 10, "Number of nodes in the cluster at snapshot time. Used to expand DaemonSets into N-replica Deployments.")
	snapshotCmd.Flags().StringVar(&snapshotCluster, "cluster", "", "Cluster name to embed in output (informational)")
	_ = snapshotCmd.MarkFlagRequired("from-velero")
}

func runSnapshot(cmd *cobra.Command, args []string) error {
	// Determine snapshot time
	var t0 time.Time
	if snapshotTime != "" {
		var err error
		t0, err = time.Parse(time.RFC3339, snapshotTime)
		if err != nil {
			return fmt.Errorf("invalid --time %q (expected RFC3339): %w", snapshotTime, err)
		}
	} else {
		t0 = time.Now()
		fmt.Printf("Warning: --time not set, using now (%s) as snapshot time.\n", t0.Format(time.RFC3339))
		fmt.Printf("  For accurate initial state, use --time matching your Velero backup timestamp.\n")
		fmt.Printf("  Find it with: velero backup get\n\n")
	}

	cluster := snapshotCluster
	if cluster == "" {
		cluster = "snapshot"
	}

	fmt.Printf("Reading Velero backup: %s\n", snapshotVeleroPath)
	fmt.Printf("Snapshot time:        %s\n", t0.Format(time.RFC3339))
	fmt.Printf("Node count (DaemonSets expand to N replicas): %d\n\n", snapshotNodeCount)

	log, stats, err := snapshot.FromVeleroArchive(snapshotVeleroPath, t0, snapshotNodeCount, cluster)
	if err != nil {
		return fmt.Errorf("reading Velero archive: %w", err)
	}

	if err := log.WriteToFile(snapshotOutput); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	fmt.Printf("Snapshot extracted:\n")
	fmt.Printf("  Deployments:  %d\n", stats.Deployments)
	fmt.Printf("  StatefulSets: %d  (converted to Deployments)\n", stats.StatefulSets)
	fmt.Printf("  DaemonSets:   %d  (converted to %d-replica Deployments)\n", stats.DaemonSets, snapshotNodeCount)
	fmt.Printf("  CronJobs:     %d  (active executions only, as Jobs)\n", stats.CronJobs)
	fmt.Printf("  Skipped:      %d  (excluded namespaces, zero replicas, inactive CronJobs)\n", stats.Skipped)
	fmt.Printf("  Total events: %d\n", len(log.Events))
	fmt.Printf("\nWritten to: %s\n", snapshotOutput)

	return nil
}
