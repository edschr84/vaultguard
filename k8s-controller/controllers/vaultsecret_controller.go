package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vaultguardv1alpha1 "github.com/vaultguard/k8s-controller/api/v1alpha1"
)

const (
	conditionReady  = "Ready"
	conditionSynced = "Synced"

	defaultRefreshInterval     = time.Hour
	defaultCredentialsSecret   = "vaultguard-credentials"
	defaultControllerNamespace = "vaultguard-system"
)

// VaultSecretReconciler reconciles VaultSecret objects.
type VaultSecretReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	ControllerNamespace string
}

// +kubebuilder:rbac:groups=vaultguard.io,resources=vaultsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vaultguard.io,resources=vaultsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch,resourceNames=vaultguard-credentials

func (r *VaultSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var vs vaultguardv1alpha1.VaultSecret
	if err := r.Get(ctx, req.NamespacedName, &vs); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	interval, err := parseInterval(vs.Spec.RefreshInterval)
	if err != nil {
		interval = defaultRefreshInterval
	}

	// Fetch Vaultguard credentials from the referenced K8s Secret.
	vgClient, err := r.vaultguardClient(ctx, &vs)
	if err != nil {
		logger.Error(err, "failed to build Vaultguard client")
		r.setCondition(&vs, conditionReady, metav1.ConditionFalse, "CredentialsError", err.Error())
		_ = r.Status().Update(ctx, &vs)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Fetch the secret from Vaultguard.
	data, version, err := vgClient.getSecret(vs.Spec.Path)
	if err != nil {
		logger.Error(err, "failed to fetch secret from Vaultguard", "path", vs.Spec.Path)
		r.setCondition(&vs, conditionSynced, metav1.ConditionFalse, "FetchError", err.Error())
		r.setCondition(&vs, conditionReady, metav1.ConditionFalse, "FetchError", err.Error())
		_ = r.Status().Update(ctx, &vs)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Write the K8s Secret.
	destNS := vs.Spec.Destination.Namespace
	if destNS == "" {
		destNS = vs.Namespace
	}
	destName := vs.Spec.Destination.Name
	secretType := corev1.SecretType(vs.Spec.Destination.Type)
	if secretType == "" {
		secretType = corev1.SecretTypeOpaque
	}

	if err := r.upsertSecret(ctx, destNS, destName, secretType, data, &vs); err != nil {
		logger.Error(err, "failed to upsert K8s Secret")
		r.setCondition(&vs, conditionReady, metav1.ConditionFalse, "WriteError", err.Error())
		_ = r.Status().Update(ctx, &vs)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	now := metav1.Now()
	vs.Status.LastSyncTime = &now
	vs.Status.LastSyncVersion = version
	vs.Status.Ready = true
	r.setCondition(&vs, conditionSynced, metav1.ConditionTrue, "Synced", "Secret synced successfully")
	r.setCondition(&vs, conditionReady, metav1.ConditionTrue, "Ready", "Destination secret is up to date")
	if err := r.Status().Update(ctx, &vs); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("synced VaultSecret", "path", vs.Spec.Path, "version", version, "destination", destNS+"/"+destName)
	return ctrl.Result{RequeueAfter: interval}, nil
}

// upsertSecret creates or updates the destination K8s Secret.
func (r *VaultSecretReconciler) upsertSecret(ctx context.Context, ns, name string, secretType corev1.SecretType, data map[string]string, owner *vaultguardv1alpha1.VaultSecret) error {
	stringData := make(map[string]string, len(data))
	for k, v := range data {
		stringData[k] = v
	}

	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "vaultguard-controller",
				"vaultguard.io/source":         owner.Name,
			},
		},
		Type:       secretType,
		StringData: stringData,
	}

	var existing corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, &existing)
	if errors.IsNotFound(err) {
		return r.Create(ctx, desired)
	}
	if err != nil {
		return err
	}

	existing.StringData = stringData
	existing.Type = secretType
	return r.Update(ctx, &existing)
}

// setCondition updates or appends a condition on the VaultSecret status.
func (r *VaultSecretReconciler) setCondition(vs *vaultguardv1alpha1.VaultSecret, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	for i, c := range vs.Status.Conditions {
		if c.Type == condType {
			vs.Status.Conditions[i].Status = status
			vs.Status.Conditions[i].Reason = reason
			vs.Status.Conditions[i].Message = message
			vs.Status.Conditions[i].LastTransitionTime = now
			return
		}
	}
	vs.Status.Conditions = append(vs.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
	})
}

func (r *VaultSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultguardv1alpha1.VaultSecret{}).
		Complete(r)
}

// ── Vaultguard HTTP client ────────────────────────────────────────────────────

type vaultguardClient struct {
	serverURL string
	token     string
	http      *http.Client
}

// vaultguardClient builds an authenticated client using the client credentials flow.
func (r *VaultSecretReconciler) vaultguardClient(ctx context.Context, vs *vaultguardv1alpha1.VaultSecret) (*vaultguardClient, error) {
	refNS := r.ControllerNamespace
	refName := defaultCredentialsSecret
	if vs.Spec.VaultguardRef != nil {
		refName = vs.Spec.VaultguardRef.Name
		if vs.Spec.VaultguardRef.Namespace != "" {
			refNS = vs.Spec.VaultguardRef.Namespace
		}
	}

	var credSecret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: refName, Namespace: refNS}, &credSecret); err != nil {
		return nil, fmt.Errorf("credentials secret %s/%s: %w", refNS, refName, err)
	}

	serverURL := strings.TrimRight(string(credSecret.Data["server_url"]), "/")
	clientID := string(credSecret.Data["client_id"])
	clientSecret := string(credSecret.Data["client_secret"])

	if serverURL == "" || clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("credentials secret must have server_url, client_id, client_secret")
	}
	u, err := url.Parse(serverURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid server_url: must be an absolute http/https URL")
	}

	token, err := fetchClientCredentialsToken(serverURL, clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("obtain access token: %w", err)
	}

	return &vaultguardClient{
		serverURL: serverURL,
		token:     token,
		http:      &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// fetchClientCredentialsToken performs an OAuth2 client_credentials token request.
func fetchClientCredentialsToken(serverURL, clientID, clientSecret string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("scope", "vault:read")
	resp, err := http.Post(serverURL+"/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(raw))
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("empty access_token in response")
	}
	return result.AccessToken, nil
}

// getSecret fetches a secret from the Vaultguard vault API.
// path format: "namespace/mount/path"
func (c *vaultguardClient) getSecret(path string) (map[string]string, int32, error) {
	req, err := http.NewRequest(http.MethodGet, c.serverURL+"/v1/"+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var e map[string]string
		if json.Unmarshal(raw, &e) == nil && e["error"] != "" {
			return nil, 0, fmt.Errorf("%s", e["error"])
		}
		return nil, 0, fmt.Errorf("vault returned %d", resp.StatusCode)
	}

	var result struct {
		Data    map[string]string `json:"data"`
		Version int32             `json:"version"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, 0, err
	}
	return result.Data, result.Version, nil
}

// parseInterval parses a Go duration string, returning defaultRefreshInterval on error.
func parseInterval(s string) (time.Duration, error) {
	if s == "" {
		return defaultRefreshInterval, nil
	}
	return time.ParseDuration(s)
}

// encodeSecretData converts string map to byte map for K8s Secret Data field.
func encodeSecretData(in map[string]string) map[string][]byte {
	out := make(map[string][]byte, len(in))
	for k, v := range in {
		out[k] = []byte(v)
	}
	return out
}

// ensure encodeSecretData is referenced (used in tests).
var _ = encodeSecretData

// ensure bytes is used.
var _ = bytes.NewReader
