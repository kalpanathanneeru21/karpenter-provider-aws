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

// Package snapshot reads a Velero backup archive (.tar.gz) and converts the
// cluster state it contains into a kubereplay ReplayLog.
//
// Velero backup layout (inside the tar.gz):
//
//	<backup-name>/
//	  resources/
//	    deployments.apps/namespaces/<ns>/<name>.json
//	    statefulsets.apps/namespaces/<ns>/<name>.json
//	    daemonsets.apps/namespaces/<ns>/<name>.json
//	    cronjobs.batch/namespaces/<ns>/<name>.json
//	    jobs.batch/  ← excluded by kaas-backup schedule, won't be present
//
// All resources are injected as T+0 (snapshot time) events so they form the
// baseline cluster state before audit-log events are layered on top via merge.
package snapshot

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/aws/karpenter-provider-aws/tools/kubereplay/pkg/format"
	"github.com/aws/karpenter-provider-aws/tools/kubereplay/pkg/sanitizer"
)

// excludedNamespaces mirrors kaas-backup's excludedNamespaces so we don't
// inject system workloads that would never land on Karpenter worker nodes.
var excludedNamespaces = map[string]bool{
	"acquia-system":          true,
	"falco-system":           true,
	"istio-system":           true,
	"pipeline-system":        true,
	"teleport-agent":         true,
	"kaas-metrics":           true,
	"stormforge-system":      true,
	"kaas-monitoring":        true,
	"kaas-rep-app":           true,
	"kaas-teleport-agent":    true,
	"acquia-polaris-system":  true,
	"kube-system":            true,
	"kube-public":            true,
	"kube-node-lease":        true,
}

// Stats tracks what was extracted from a Velero backup.
type Stats struct {
	Deployments  int
	StatefulSets int // converted to equivalent Deployments
	DaemonSets   int // converted to N-replica Deployments (N=nodeCount)
	CronJobs     int // converted to single Jobs
	Skipped      int // excluded namespace or zero replicas
}

// FromVeleroArchive reads a Velero backup tar.gz file and returns a ReplayLog
// containing all workloads as T+0 create events.
//
// nodeCount is used to expand DaemonSets: a DaemonSet with 1 pod template
// becomes a Deployment with nodeCount replicas to approximate the total
// resource pressure DaemonSet pods impose across all nodes.
func FromVeleroArchive(path string, snapshotTime time.Time, nodeCount int, cluster string) (*format.ReplayLog, Stats, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, Stats{}, fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, Stats{}, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	san := sanitizer.NewWithPrefix("snap")   // "snap-deployment-N" avoids name collisions with capture output
	log := format.NewReplayLog(cluster)
	var stats Stats

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, Stats{}, fmt.Errorf("reading tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// Only process .json files under resources/
		// Path format: <backup>/resources/<resource.group>/namespaces/<ns>/<name>.json
		if filepath.Ext(hdr.Name) != ".json" {
			continue
		}
		if !strings.Contains(hdr.Name, "resources/") {
			continue
		}

		// Parse resource type from path
		resourceType := resourceTypeFromPath(hdr.Name)
		if resourceType == "" {
			continue
		}

		// Parse namespace from path
		ns := namespaceFromPath(hdr.Name)
		if excludedNamespaces[ns] {
			stats.Skipped++
			continue
		}

		// Read file content
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, Stats{}, fmt.Errorf("reading %s: %w", hdr.Name, err)
		}

		switch resourceType {
		case "deployments":
			dep, err := parseDeployment(data)
			if err != nil || dep == nil {
				continue
			}
			if replicas(dep.Spec.Replicas) == 0 {
				stats.Skipped++
				continue
			}
			sanitized := san.SanitizeDeployment(dep)
			log.AddDeploymentCreate(sanitized, snapshotTime)
			stats.Deployments++

		case "statefulsets":
			sts, err := parseStatefulSet(data)
			if err != nil || sts == nil {
				continue
			}
			if replicas(sts.Spec.Replicas) == 0 {
				stats.Skipped++
				continue
			}
			// Convert StatefulSet → Deployment with same replica count + resources.
			// StatefulSet pod pressure on nodes is what matters for Karpenter.
			dep := statefulSetToDeployment(sts)
			sanitized := san.SanitizeDeployment(dep)
			log.AddDeploymentCreate(sanitized, snapshotTime)
			stats.StatefulSets++

		case "daemonsets":
			ds, err := parseDaemonSet(data)
			if err != nil || ds == nil {
				continue
			}
			if nodeCount <= 0 {
				// No node count available — use 1 replica as minimum estimate
				nodeCount = 1
			}
			// Convert DaemonSet → Deployment with nodeCount replicas.
			// This approximates total resource pressure: in prod a DaemonSet pod
			// runs on every node, so nodeCount replicas represents the same total.
			dep := daemonSetToDeployment(ds, int32(nodeCount))
			sanitized := san.SanitizeDeployment(dep)
			log.AddDeploymentCreate(sanitized, snapshotTime)
			stats.DaemonSets++

		case "cronjobs":
			cj, err := parseCronJob(data)
			if err != nil || cj == nil {
				continue
			}
			// Convert CronJob → single Job representing one execution.
			// CronJobs themselves don't consume resources — their triggered Jobs do.
			// We inject one Job to represent a currently-running execution if the
			// CronJob has active jobs; otherwise we skip it (no resource pressure).
			if len(cj.Status.Active) == 0 {
				stats.Skipped++
				continue
			}
			job := cronJobToJob(cj)
			sanitized := san.SanitizeJob(job)
			log.AddJobCreate(sanitized, snapshotTime)
			stats.CronJobs++
		}
	}

	return log, stats, nil
}

// resourceTypeFromPath extracts the resource type from a Velero tar path.
// e.g. "backup/resources/deployments.apps/namespaces/default/my-app.json" → "deployments"
func resourceTypeFromPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, p := range parts {
		if p == "resources" && i+1 < len(parts) {
			// resource entry is like "deployments.apps" or "statefulsets.apps"
			resource := strings.Split(parts[i+1], ".")[0]
			return resource
		}
	}
	return ""
}

// namespaceFromPath extracts the namespace from a Velero tar path.
// e.g. "backup/resources/deployments.apps/namespaces/default/my-app.json" → "default"
func namespaceFromPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, p := range parts {
		if p == "namespaces" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func replicas(r *int32) int32 {
	if r == nil {
		return 1
	}
	return *r
}

// ── parsers ────────────────────────────────────────────────────────────────────

func parseDeployment(data []byte) (*appsv1.Deployment, error) {
	var dep appsv1.Deployment
	if err := json.Unmarshal(data, &dep); err != nil {
		return nil, err
	}
	if dep.Kind != "" && dep.Kind != "Deployment" {
		return nil, nil
	}
	return &dep, nil
}

func parseStatefulSet(data []byte) (*appsv1.StatefulSet, error) {
	var sts appsv1.StatefulSet
	if err := json.Unmarshal(data, &sts); err != nil {
		return nil, err
	}
	return &sts, nil
}

func parseDaemonSet(data []byte) (*appsv1.DaemonSet, error) {
	var ds appsv1.DaemonSet
	if err := json.Unmarshal(data, &ds); err != nil {
		return nil, err
	}
	return &ds, nil
}

func parseCronJob(data []byte) (*batchv1.CronJob, error) {
	var cj batchv1.CronJob
	if err := json.Unmarshal(data, &cj); err != nil {
		return nil, err
	}
	return &cj, nil
}

// ── converters ────────────────────────────────────────────────────────────────

// statefulSetToDeployment converts a StatefulSet to an equivalent Deployment.
// Only the scheduling-relevant fields are carried over: replicas, pod template
// spec (resources, affinity, topology constraints, node selector, tolerations).
// VolumeClaimTemplates are dropped — we only care about compute pressure.
func statefulSetToDeployment(sts *appsv1.StatefulSet) *appsv1.Deployment {
	r := replicas(sts.Spec.Replicas)
	return &appsv1.Deployment{
		ObjectMeta: sts.ObjectMeta,
		Spec: appsv1.DeploymentSpec{
			Replicas: &r,
			Selector: sts.Spec.Selector,
			Template: podTemplateWithoutVolumes(sts.Spec.Template),
		},
	}
}

// daemonSetToDeployment converts a DaemonSet to a Deployment with nodeCount replicas.
// Each DaemonSet pod runs on one node, so nodeCount replicas approximates
// the total resource consumption across the cluster.
func daemonSetToDeployment(ds *appsv1.DaemonSet, nodeCount int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: ds.ObjectMeta,
		Spec: appsv1.DeploymentSpec{
			Replicas: &nodeCount,
			Selector: ds.Spec.Selector,
			// DaemonSet pods don't use affinity/topology the same way —
			// but their resource requests per pod still affect bin-packing.
			// We use a clean template with just the resource requests.
			Template: podTemplateWithoutVolumes(ds.Spec.Template),
		},
	}
}

// cronJobToJob converts a CronJob's job template to a Job representing one execution.
func cronJobToJob(cj *batchv1.CronJob) *batchv1.Job {
	spec := cj.Spec.JobTemplate.Spec
	spec.Template = podTemplateWithoutVolumes(spec.Template)
	return &batchv1.Job{
		ObjectMeta: cj.ObjectMeta,
		Spec:       spec,
	}
}

// podTemplateWithoutVolumes strips volume-related fields from a pod template
// that would prevent scheduling on the replay cluster (missing PVCs, secrets, etc.)
// while preserving all compute/scheduling-relevant fields.
func podTemplateWithoutVolumes(tmpl corev1.PodTemplateSpec) corev1.PodTemplateSpec {
	tmpl.Spec.Volumes = nil
	tmpl.Spec.ImagePullSecrets = nil
	// Strip volume mounts from containers but keep resource requests
	for i := range tmpl.Spec.Containers {
		tmpl.Spec.Containers[i].VolumeMounts = nil
		tmpl.Spec.Containers[i].EnvFrom = nil // strip secretRef/configMapRef env sources
	}
	for i := range tmpl.Spec.InitContainers {
		tmpl.Spec.InitContainers[i].VolumeMounts = nil
		tmpl.Spec.InitContainers[i].EnvFrom = nil
	}
	return tmpl
}
