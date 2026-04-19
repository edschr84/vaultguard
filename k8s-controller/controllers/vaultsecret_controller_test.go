package controllers

import (
	"testing"
	"time"

	vaultguardv1alpha1 "github.com/vaultguard/k8s-controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestParseInterval(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"1h", time.Hour},
		{"30m", 30 * time.Minute},
		{"", defaultRefreshInterval},
		{"bad", defaultRefreshInterval},
	}
	for _, tc := range cases {
		got, err := parseInterval(tc.in)
		if err != nil {
			got = defaultRefreshInterval
		}
		if got != tc.want {
			t.Errorf("parseInterval(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSetCondition(t *testing.T) {
	r := &VaultSecretReconciler{}
	vs := &vaultguardv1alpha1.VaultSecret{}

	r.setCondition(vs, conditionReady, metav1.ConditionFalse, "FetchError", "connection refused")
	if len(vs.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(vs.Status.Conditions))
	}
	if vs.Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Errorf("status = %v, want False", vs.Status.Conditions[0].Status)
	}

	// Update existing condition — should not append
	r.setCondition(vs, conditionReady, metav1.ConditionTrue, "Ready", "ok")
	if len(vs.Status.Conditions) != 1 {
		t.Errorf("expected 1 condition after update, got %d", len(vs.Status.Conditions))
	}
	if vs.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Errorf("status after update = %v, want True", vs.Status.Conditions[0].Status)
	}

	// Add a second distinct condition
	r.setCondition(vs, conditionSynced, metav1.ConditionTrue, "Synced", "ok")
	if len(vs.Status.Conditions) != 2 {
		t.Errorf("expected 2 conditions, got %d", len(vs.Status.Conditions))
	}
}

func TestEncodeSecretData(t *testing.T) {
	in := map[string]string{"user": "robot", "pass": "s3cr3t"}
	out := encodeSecretData(in)
	if string(out["user"]) != "robot" {
		t.Errorf("user = %q", string(out["user"]))
	}
	if string(out["pass"]) != "s3cr3t" {
		t.Errorf("pass = %q", string(out["pass"]))
	}
}
