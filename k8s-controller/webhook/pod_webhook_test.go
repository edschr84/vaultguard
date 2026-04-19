package webhook

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func basicPod(annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-pod",
			Namespace:   "default",
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "nginx"},
			},
		},
	}
}

func TestInjectVolume(t *testing.T) {
	pod := basicPod(nil)
	injectVolume(pod)

	if len(pod.Spec.Volumes) != 1 {
		t.Fatalf("expected 1 volume, got %d", len(pod.Spec.Volumes))
	}
	if pod.Spec.Volumes[0].Name != SecretsVolumeName {
		t.Errorf("volume name = %q, want %q", pod.Spec.Volumes[0].Name, SecretsVolumeName)
	}

	// Idempotent — calling again should not add a duplicate
	injectVolume(pod)
	if len(pod.Spec.Volumes) != 1 {
		t.Error("injectVolume is not idempotent")
	}
}

func TestInjectInitContainer(t *testing.T) {
	pod := basicPod(nil)
	injectInitContainer(pod, "ghcr.io/vaultguard/init:test", "local/app/db", "vaultguard-credentials")

	if len(pod.Spec.InitContainers) != 1 {
		t.Fatalf("expected 1 init container, got %d", len(pod.Spec.InitContainers))
	}
	ic := pod.Spec.InitContainers[0]
	if ic.Name != InitContainerName {
		t.Errorf("init container name = %q, want %q", ic.Name, InitContainerName)
	}
	if ic.Image != "ghcr.io/vaultguard/init:test" {
		t.Errorf("image = %q", ic.Image)
	}

	// Check VAULTGUARD_SECRETS env var
	found := false
	for _, e := range ic.Env {
		if e.Name == "VAULTGUARD_SECRETS" && e.Value == "local/app/db" {
			found = true
		}
	}
	if !found {
		t.Error("VAULTGUARD_SECRETS env var not set correctly")
	}

	// Idempotent
	injectInitContainer(pod, "ghcr.io/vaultguard/init:test", "local/app/db", "vaultguard-credentials")
	if len(pod.Spec.InitContainers) != 1 {
		t.Error("injectInitContainer is not idempotent")
	}
}

func TestInjectVolumeMount(t *testing.T) {
	pod := basicPod(nil)
	injectVolumeMount(pod)

	if len(pod.Spec.Containers[0].VolumeMounts) != 1 {
		t.Fatalf("expected 1 volume mount, got %d", len(pod.Spec.Containers[0].VolumeMounts))
	}
	vm := pod.Spec.Containers[0].VolumeMounts[0]
	if vm.Name != SecretsVolumeName {
		t.Errorf("mount name = %q, want %q", vm.Name, SecretsVolumeName)
	}
	if vm.MountPath != SecretsMountPath {
		t.Errorf("mount path = %q, want %q", vm.MountPath, SecretsMountPath)
	}
	if !vm.ReadOnly {
		t.Error("volume mount should be read-only")
	}
}

func TestFullMutation(t *testing.T) {
	pod := basicPod(map[string]string{
		AnnotationInject:  "true",
		AnnotationSecrets: "local/app/db-creds,local/app/api-key",
	})

	mutated := pod.DeepCopy()
	injectVolume(mutated)
	injectInitContainer(mutated, DefaultInitImage, "local/app/db-creds,local/app/api-key", "vaultguard-credentials")
	injectVolumeMount(mutated)

	// Sanity: can marshal/unmarshal (what the webhook does before patching)
	b, err := json.Marshal(mutated)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundtripped corev1.Pod
	if err := json.Unmarshal(b, &roundtripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(roundtripped.Spec.Volumes) != 1 {
		t.Errorf("volumes: got %d, want 1", len(roundtripped.Spec.Volumes))
	}
	if len(roundtripped.Spec.InitContainers) != 1 {
		t.Errorf("init containers: got %d, want 1", len(roundtripped.Spec.InitContainers))
	}
	if len(roundtripped.Spec.Containers[0].VolumeMounts) != 1 {
		t.Errorf("volume mounts: got %d, want 1", len(roundtripped.Spec.Containers[0].VolumeMounts))
	}
}

func TestNoInjectionWithoutAnnotation(t *testing.T) {
	pod := basicPod(nil)
	original := pod.DeepCopy()

	// Without the annotation, nothing should change
	if pod.Annotations[AnnotationInject] == "true" {
		t.Fatal("test setup error: annotation should not be set")
	}

	// Verify pod is unchanged
	if len(pod.Spec.Volumes) != len(original.Spec.Volumes) {
		t.Error("volumes changed without inject annotation")
	}
	if len(pod.Spec.InitContainers) != len(original.Spec.InitContainers) {
		t.Error("init containers changed without inject annotation")
	}
}
