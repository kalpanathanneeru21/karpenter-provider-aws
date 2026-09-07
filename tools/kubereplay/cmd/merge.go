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

	"github.com/spf13/cobra"

	"github.com/aws/karpenter-provider-aws/tools/kubereplay/pkg/format"
)

var mergeCmd = &cobra.Command{
	Use:   "merge",
	Short: "Merge a Velero snapshot baseline with a capture events file",
	Long: `merge combines two replay logs into one:
  --snapshot  T+0 baseline from "kubereplay snapshot" (Velero backup state)
  --events    Timed events from "kubereplay capture" (audit log traffic)

The merged output has snapshot events at T+0 followed by capture events at
their original timestamps. This gives Karpenter an accurate initial cluster
load before new traffic arrives on top.

Deduplication: if a deployment appears in both snapshot and capture (because
it was updated during the capture window and captured as PreExisting), the
capture version wins.

Example:
  kubereplay merge \
    --snapshot snapshot.json \
    --events   events.json \
    --output   full-replay.json`,
	RunE: runMerge,
}

var (
	mergeSnapshotFile string
	mergeEventsFile   string
	mergeOutput       string
)

func init() {
	mergeCmd.Flags().StringVar(&mergeSnapshotFile, "snapshot", "", "Snapshot file from 'kubereplay snapshot' (required)")
	mergeCmd.Flags().StringVar(&mergeEventsFile, "events", "", "Events file from 'kubereplay capture' (required)")
	mergeCmd.Flags().StringVarP(&mergeOutput, "output", "o", "full-replay.json", "Output merged replay file")
	_ = mergeCmd.MarkFlagRequired("snapshot")
	_ = mergeCmd.MarkFlagRequired("events")
}

func runMerge(cmd *cobra.Command, args []string) error {
	snapshotLog, err := format.ReadFromFile(mergeSnapshotFile)
	if err != nil {
		return fmt.Errorf("reading snapshot %s: %w", mergeSnapshotFile, err)
	}

	eventsLog, err := format.ReadFromFile(mergeEventsFile)
	if err != nil {
		return fmt.Errorf("reading events %s: %w", mergeEventsFile, err)
	}

	merged := format.Merge(snapshotLog, eventsLog)

	if err := merged.WriteToFile(mergeOutput); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	// Summary
	var snapshotEvents, captureEvents, deployments, jobs, scale int
	for _, e := range snapshotLog.Events {
		snapshotEvents++
		_ = e
	}
	for _, e := range eventsLog.Events {
		captureEvents++
		_ = e
	}
	for _, e := range merged.Events {
		switch {
		case e.Type == format.EventCreate && e.Kind == format.KindDeployment:
			deployments++
		case e.Type == format.EventCreate && e.Kind == format.KindJob:
			jobs++
		case e.Type == format.EventScale:
			scale++
		}
	}

	fmt.Printf("Merged:\n")
	fmt.Printf("  Snapshot events: %d  (T+0 baseline)\n", snapshotEvents)
	fmt.Printf("  Capture events:  %d  (timed traffic)\n", captureEvents)
	fmt.Printf("  Total events:    %d\n", len(merged.Events))
	fmt.Printf("  Deployments:     %d\n", deployments)
	fmt.Printf("  Jobs:            %d\n", jobs)
	fmt.Printf("  Scale events:    %d\n", scale)
	fmt.Printf("\nWritten to: %s\n", mergeOutput)

	return nil
}
