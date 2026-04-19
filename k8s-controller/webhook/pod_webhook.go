// Package webhook implements a mutating admission webhook that injects a
// Vaultguard init container into pods annotated with vaultguard.io/inject="true".
//
// The init container mounts an emptyDir at /vault/secrets and runs
// docker-credential-vaultguard (or a dedicated fetch binary) to write secrets
// to files before the main container starts.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// ensure client is used
var _ client.Client

const (
	// AnnotationInject triggers sidecar injection when set to "true".
	AnnotationInject = "vaultguard.io/inject"

	// AnnotationSecrets is a comma-separated list of vault paths to fetch.
	// e.g. "local/app/db-creds,local/app/api-key"
	AnnotationSecrets = "vaultguard.io/secrets"

	// AnnotationCredentialsSecret names the K8s Secret holding Vaultguard client creds.
	AnnotationCredentialsSecret = "vaultguard.io/credentials-secret"

	// SecretsVolumeName is the emptyDir volume name shared with the init container.
	SecretsVolumeName = "vaultguard-secrets"

	// SecretsMountPath is where secrets are written inside the container.
	SecretsMountPath = "/vault/secrets"

	// InitContainerName is the name of the injected init container.
	InitContainerName = "vaultguard-init"

	// DefaultInitImage is the image used for the init container.
	DefaultInitImage = "ghcr.io/vaultguard/init:latest"
)

// PodMutator mutates pods to inject the Vaultguard init container.
type PodMutator struct {
	Client    client.Client
	Dec       admission.Decoder
	InitImage string
}

func (m *PodMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}
	if err := m.Dec.DecodeRaw(req.Object, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	if pod.Annotations[AnnotationInject] != "true" {
		return admission.Allowed("injection not requested")
	}

	secretPaths := pod.Annotations[AnnotationSecrets]
	if secretPaths == "" {
		return admission.Denied(fmt.Sprintf("annotation %s is required when %s=true", AnnotationSecrets, AnnotationInject))
	}

	credSecret := pod.Annotations[AnnotationCredentialsSecret]
	if credSecret == "" {
		credSecret = "vaultguard-credentials"
	}

	image := m.InitImage
	if image == "" {
		image = DefaultInitImage
	}

	mutated := pod.DeepCopy()
	injectVolume(mutated)
	injectInitContainer(mutated, image, secretPaths, credSecret)
	injectVolumeMount(mutated)

	marshalled, err := json.Marshal(mutated)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, marshalled)
}

// injectVolume adds the shared emptyDir volume if not already present.
func injectVolume(pod *corev1.Pod) {
	for _, v := range pod.Spec.Volumes {
		if v.Name == SecretsVolumeName {
			return
		}
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: SecretsVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})
}

// injectInitContainer prepends the Vaultguard init container if not already present.
func injectInitContainer(pod *corev1.Pod, image, secretPaths, credSecret string) {
	for _, c := range pod.Spec.InitContainers {
		if c.Name == InitContainerName {
			return
		}
	}

	initContainer := corev1.Container{
		Name:  InitContainerName,
		Image: image,
		// VAULTGUARD_SECRETS is a colon-separated list of vault paths to fetch.
		// The init binary writes each as a file: /vault/secrets/<last-path-segment>
		Env: []corev1.EnvVar{
			{
				Name:  "VAULTGUARD_SECRETS",
				Value: secretPaths,
			},
			{
				Name: "VAULTGUARD_SERVER_URL",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: credSecret},
						Key:                  "server_url",
					},
				},
			},
			{
				Name: "VAULTGUARD_CLIENT_ID",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: credSecret},
						Key:                  "client_id",
					},
				},
			},
			{
				Name: "VAULTGUARD_CLIENT_SECRET",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: credSecret},
						Key:                  "client_secret",
					},
				},
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      SecretsVolumeName,
				MountPath: SecretsMountPath,
			},
		},
	}

	pod.Spec.InitContainers = append([]corev1.Container{initContainer}, pod.Spec.InitContainers...)
}

// injectVolumeMount adds the secrets volume mount to all app containers that don't have it.
func injectVolumeMount(pod *corev1.Pod) {
	mount := corev1.VolumeMount{
		Name:      SecretsVolumeName,
		MountPath: SecretsMountPath,
		ReadOnly:  true,
	}
	for i := range pod.Spec.Containers {
		has := false
		for _, vm := range pod.Spec.Containers[i].VolumeMounts {
			if vm.Name == SecretsVolumeName {
				has = true
				break
			}
		}
		if !has {
			pod.Spec.Containers[i].VolumeMounts = append(pod.Spec.Containers[i].VolumeMounts, mount)
		}
	}
}
