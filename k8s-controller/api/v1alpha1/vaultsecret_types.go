package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultSecretSpec defines the desired state of a VaultSecret.
type VaultSecretSpec struct {
	// Path is the Vaultguard vault path in the form "namespace/mount/path".
	// +kubebuilder:validation:Required
	Path string `json:"path"`

	// RefreshInterval controls how often the secret is re-synced from Vaultguard.
	// Defaults to 1h. Use Go duration strings (e.g. "30m", "2h").
	// +kubebuilder:default="1h"
	RefreshInterval string `json:"refreshInterval,omitempty"`

	// Destination describes the Kubernetes Secret to write.
	// +kubebuilder:validation:Required
	Destination SecretDestination `json:"destination"`

	// VaultguardRef points at the K8s Secret holding Vaultguard client credentials.
	// The Secret must have keys: server_url, client_id, client_secret.
	// Defaults to "vaultguard-credentials" in the controller namespace.
	// +optional
	VaultguardRef *SecretRef `json:"vaultguardRef,omitempty"`
}

// SecretDestination describes the K8s Secret the controller will create/update.
type SecretDestination struct {
	// Name of the K8s Secret to write.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Namespace of the destination Secret. Defaults to the VaultSecret namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Type is the K8s Secret type. Defaults to Opaque.
	// +kubebuilder:default="Opaque"
	Type string `json:"type,omitempty"`
}

// SecretRef is a reference to a K8s Secret.
type SecretRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// VaultSecretStatus defines the observed state of a VaultSecret.
type VaultSecretStatus struct {
	// LastSyncTime is when the secret was last successfully synced.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// LastSyncVersion is the vault secret version that was last synced.
	// +optional
	LastSyncVersion int32 `json:"lastSyncVersion,omitempty"`

	// Ready is true when the destination K8s Secret exists and is up to date.
	Ready bool `json:"ready"`

	// Conditions holds standard condition types (Ready, Synced).
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Path",type=string,JSONPath=`.spec.path`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Last Sync",type=string,JSONPath=`.status.lastSyncTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VaultSecret syncs a secret from Vaultguard into a Kubernetes Secret.
type VaultSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultSecretSpec   `json:"spec,omitempty"`
	Status VaultSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultSecretList contains a list of VaultSecret.
type VaultSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultSecret{}, &VaultSecretList{})
}
