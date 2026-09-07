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

package sanitizer

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/samber/lo"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const Namespace = "kubereplay"

// Sanitizer transforms workloads for replay by stripping unnecessary fields
type Sanitizer struct {
	deploymentCounter atomic.Uint64
	jobCounter        atomic.Uint64
	// prefix is prepended to all generated names to avoid collisions between
	// snapshot and capture outputs when they are merged.
	// Empty string = default behaviour (deployment-N, job-N).
	// "snap" = snap-deployment-N, snap-job-N.
	prefix string
	// keyMapping tracks original key -> sanitized key for scale event correlation
	keyMapping map[string]string
}

// New creates a new workload sanitizer with default naming (deployment-N, job-N)
func New() *Sanitizer {
	return &Sanitizer{
		keyMapping: make(map[string]string),
	}
}

// NewWithPrefix creates a sanitizer that prefixes all generated names.
// Use "snap" for snapshot outputs so names don't collide with capture outputs
// when the two are merged: snap-deployment-0 vs deployment-0.
func NewWithPrefix(prefix string) *Sanitizer {
	return &Sanitizer{
		prefix:     prefix,
		keyMapping: make(map[string]string),
	}
}

// GetSanitizedKey returns the sanitized key for an original deployment key.
// This is used to correlate scale events with their sanitized deployments.
func (s *Sanitizer) GetSanitizedKey(originalKey string) (string, bool) {
	key, ok := s.keyMapping[originalKey]
	return key, ok
}

// SanitizeDeployment creates a sanitized copy of a deployment suitable for replay
func (s *Sanitizer) SanitizeDeployment(deployment *appsv1.Deployment) *appsv1.Deployment {
	seqID := s.deploymentCounter.Add(1) - 1

	baseName := fmt.Sprintf("deployment-%d", seqID)
	if s.prefix != "" {
		baseName = fmt.Sprintf("%s-deployment-%d", s.prefix, seqID)
	}

	newDeploy := deployment.DeepCopy()

	// Track original -> sanitized key mapping for scale event correlation
	originalKey := deployment.Namespace + "/" + deployment.Name
	sanitizedKey := Namespace + "/" + baseName
	s.keyMapping[originalKey] = sanitizedKey

	// Set new name and namespace
	newDeploy.Name = baseName
	newDeploy.Namespace = Namespace

	// Add tracking label
	if newDeploy.Labels == nil {
		newDeploy.Labels = map[string]string{}
	}
	newDeploy.Labels["kubereplay.karpenter.sh/managed"] = "true"

	// Clear metadata
	clearObjectMeta(&newDeploy.ObjectMeta)

	// Preserve Karpenter annotations
	newDeploy.Annotations = filterKarpenterAnnotations(deployment.Annotations)

	// Update selector and template labels to match new name
	appLabel := fmt.Sprintf("app-%d", seqID)
	if s.prefix != "" {
		appLabel = fmt.Sprintf("%s-app-%d", s.prefix, seqID)
	}
	newDeploy.Spec.Selector = &metav1.LabelSelector{
		MatchLabels: map[string]string{
			"app": appLabel,
		},
	}

	// Sanitize pod template
	newDeploy.Spec.Template = sanitizePodTemplateSpec(newDeploy.Spec.Template, appLabel, false)

	// Clear status
	newDeploy.Status = appsv1.DeploymentStatus{}

	return newDeploy
}

// SanitizeJob creates a sanitized copy of a job suitable for replay
func (s *Sanitizer) SanitizeJob(job *batchv1.Job) *batchv1.Job {
	seqID := s.jobCounter.Add(1) - 1

	baseName := fmt.Sprintf("job-%d", seqID)
	if s.prefix != "" {
		baseName = fmt.Sprintf("%s-job-%d", s.prefix, seqID)
	}

	newJob := job.DeepCopy()

	// Set new name and namespace
	newJob.Name = baseName
	newJob.Namespace = Namespace

	// Add tracking label
	if newJob.Labels == nil {
		newJob.Labels = map[string]string{}
	}
	newJob.Labels["kubereplay.karpenter.sh/managed"] = "true"

	// Clear metadata
	clearObjectMeta(&newJob.ObjectMeta)

	// Preserve Karpenter annotations
	newJob.Annotations = filterKarpenterAnnotations(job.Annotations)

	// Update selector and template labels to match new name
	appLabel := fmt.Sprintf("job-%d", seqID)

	// Jobs auto-generate selectors, so we clear it to let k8s regenerate
	newJob.Spec.Selector = nil

	// Sanitize pod template (forJob=true so containers exit)
	newJob.Spec.Template = sanitizePodTemplateSpec(newJob.Spec.Template, appLabel, true)

	// Clear TTL (we manage cleanup)
	newJob.Spec.TTLSecondsAfterFinished = nil

	// Clear status
	newJob.Status = batchv1.JobStatus{}

	return newJob
}

func clearObjectMeta(meta *metav1.ObjectMeta) {
	meta.UID = ""
	meta.ResourceVersion = ""
	meta.CreationTimestamp = metav1.Time{}
	meta.DeletionTimestamp = nil
	meta.DeletionGracePeriodSeconds = nil
	meta.OwnerReferences = nil
	meta.Finalizers = nil
	meta.ManagedFields = nil
	meta.Generation = 0
	meta.GenerateName = ""
}

func sanitizePodTemplateSpec(template corev1.PodTemplateSpec, appLabel string, forJob bool) corev1.PodTemplateSpec {
	// Clear auto-generated labels (Job controller labels, etc.) and set fresh ones
	// We keep Karpenter labels if any
	karpenterLabels := lo.PickBy(template.Labels, func(v string, k string) bool {
		return strings.HasPrefix(k, "karpenter.sh/")
	})
	template.Labels = map[string]string{
		"app":                              appLabel,
		"kubereplay.karpenter.sh/managed": "true",
	}
	for k, v := range karpenterLabels {
		template.Labels[k] = v
	}

	// Preserve Karpenter annotations on pod template
	template.Annotations = filterKarpenterAnnotations(template.Annotations)

	// Sanitize containers (jobs need containers that exit, deployments use pause)
	template.Spec.Containers = sanitizeContainers(template.Spec.Containers, forJob)
	template.Spec.InitContainers = nil // Jobs don't need init containers for replay

	// Clear non-scheduling fields
	template.Spec.ServiceAccountName = "default"
	template.Spec.AutomountServiceAccountToken = lo.ToPtr(false)
	template.Spec.Volumes = nil
	template.Spec.ImagePullSecrets = nil
	template.Spec.HostNetwork = false
	template.Spec.HostPID = false
	template.Spec.HostIPC = false
	template.Spec.SecurityContext = nil
	template.Spec.DNSPolicy = corev1.DNSDefault
	template.Spec.DNSConfig = nil
	template.Spec.Hostname = ""
	template.Spec.Subdomain = ""
	template.Spec.NodeName = ""

	// Keep scheduling-relevant fields that are portable across clusters:
	// - NodeSelector         (cluster-specific keys stripped below)
	// - Affinity             (sanitized below — anti-karpenter rules stripped)
	// - Tolerations          (cluster-specific keys stripped below)
	// - TopologySpreadConstraints
	// - PriorityClassName
	// - Resources (in containers)

	// Strip cluster-specific node selectors that only exist on real EKS/kaas nodes.
	// These would keep pods Pending forever on a kwok cluster.
	// We keep only generic kubernetes.io/* and karpenter.sh/* selectors.
	template.Spec.NodeSelector = filterPortableNodeSelector(template.Spec.NodeSelector)

	// Sanitize nodeAffinity: strip expressions that would prevent scheduling on
	// Karpenter nodes. On the replay cluster ALL nodes are Karpenter-provisioned,
	// so rules like "karpenter.sh/nodepool DoesNotExist" (placed on non-Karpenter
	// nodes in prod) would keep every pod Pending forever.
	template.Spec.Affinity = filterPortableAffinity(template.Spec.Affinity)

	// Strip cluster-specific tolerations (kaas.acquia.io/*, node-role.kaas.acquia.io/*).
	// Keep standard kubernetes.io tolerations and karpenter.sh tolerations.
	template.Spec.Tolerations = filterPortableTolerations(template.Spec.Tolerations)

	return template
}

// portableSelectorPrefixes are the only nodeSelector key prefixes we keep.
// Everything else (kaas.acquia.io/*, node-role.kaas.acquia.io/*, etc.) is
// cluster-specific and will prevent scheduling on kwok/non-prod nodes.
// topology.kubernetes.io/zone is excluded intentionally: kwok uses synthetic
// zone names (test-zone-a/b/c/d) that don't match real AWS zones, so zone
// nodeSelectors would keep pods Pending. Zone topology spread constraints
// (in topologySpreadConstraints) are kept — Karpenter handles those.
var portableSelectorPrefixes = []string{
	"kubernetes.io/",
	"karpenter.sh/",
	"karpenter.k8s.aws/",
	"node.kubernetes.io/",
	"beta.kubernetes.io/",
}

func filterPortableNodeSelector(ns map[string]string) map[string]string {
	if len(ns) == 0 {
		return nil
	}
	out := make(map[string]string)
	for k, v := range ns {
		if isPortableKey(k) {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func filterPortableTolerations(tolerations []corev1.Toleration) []corev1.Toleration {
	return lo.Filter(tolerations, func(t corev1.Toleration, _ int) bool {
		// Keep empty-key tolerations (e.g. tolerate all taints)
		if t.Key == "" {
			return true
		}
		return isPortableKey(t.Key)
	})
}

func isPortableKey(key string) bool {
	for _, prefix := range portableSelectorPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// filterPortableAffinity removes nodeAffinity expressions that would prevent
// pods from scheduling on Karpenter-managed nodes in the replay cluster.
//
// Specifically it strips matchExpressions with operator=DoesNotExist on
// karpenter.sh/* keys. In prod these are used to pin workloads to non-Karpenter
// (static) nodes. On the replay cluster every node is Karpenter-managed, so
// such rules make pods unschedulable.
//
// Pod affinity/anti-affinity and topology spread constraints are kept — they
// are meaningful for Karpenter bin-packing simulation.
func filterPortableAffinity(affinity *corev1.Affinity) *corev1.Affinity {
	if affinity == nil {
		return nil
	}
	result := affinity.DeepCopy()
	if result.NodeAffinity == nil {
		return result
	}

	na := result.NodeAffinity
	if na.RequiredDuringSchedulingIgnoredDuringExecution != nil {
		var keepTerms []corev1.NodeSelectorTerm
		for _, term := range na.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
			filtered := filterNodeSelectorTerm(term)
			// Only keep the term if it still has expressions after filtering;
			// an empty term would match any node which changes semantics.
			if len(filtered.MatchExpressions) > 0 || len(filtered.MatchFields) > 0 {
				keepTerms = append(keepTerms, filtered)
			}
		}
		if len(keepTerms) == 0 {
			// All terms were anti-karpenter rules — drop the required affinity entirely
			na.RequiredDuringSchedulingIgnoredDuringExecution = nil
		} else {
			na.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms = keepTerms
		}
	}

	// Filter preferred terms too
	var keepPreferred []corev1.PreferredSchedulingTerm
	for _, pref := range na.PreferredDuringSchedulingIgnoredDuringExecution {
		filtered := filterNodeSelectorTerm(pref.Preference)
		if len(filtered.MatchExpressions) > 0 || len(filtered.MatchFields) > 0 {
			keepPreferred = append(keepPreferred, corev1.PreferredSchedulingTerm{
				Weight:     pref.Weight,
				Preference: filtered,
			})
		}
	}
	na.PreferredDuringSchedulingIgnoredDuringExecution = keepPreferred

	return result
}

// filterNodeSelectorTerm removes matchExpressions that use DoesNotExist on
// karpenter.sh/* keys — these block scheduling on Karpenter nodes.
func filterNodeSelectorTerm(term corev1.NodeSelectorTerm) corev1.NodeSelectorTerm {
	var keep []corev1.NodeSelectorRequirement
	for _, expr := range term.MatchExpressions {
		// Strip: karpenter.sh/* with DoesNotExist — anti-karpenter node rules
		if strings.HasPrefix(expr.Key, "karpenter.sh/") &&
			expr.Operator == corev1.NodeSelectorOpDoesNotExist {
			continue
		}
		// Strip: kaas.acquia.io/* and node-role.kaas.acquia.io/* — cluster-specific
		if !isPortableKey(expr.Key) {
			continue
		}
		keep = append(keep, expr)
	}
	term.MatchExpressions = keep
	return term
}

func sanitizeContainers(containers []corev1.Container, forJob bool) []corev1.Container {
	return lo.Map(containers, func(c corev1.Container, i int) corev1.Container {
		container := corev1.Container{
			Name:      fmt.Sprintf("container-%d", i),
			Resources: c.Resources,
		}
		if forJob {
			// Jobs need containers that exit so they can complete
			container.Image = "busybox:1.36"
			container.Command = []string{"sh", "-c", "sleep 10"}
		} else {
			// Deployments use pause (runs forever)
			container.Image = "registry.k8s.io/pause:3.9"
		}
		return container
	})
}

func filterKarpenterAnnotations(annotations map[string]string) map[string]string {
	result := lo.PickBy(annotations, func(v string, k string) bool {
		return strings.HasPrefix(k, "karpenter.sh/")
	})
	if len(result) == 0 {
		return nil
	}
	return result
}
