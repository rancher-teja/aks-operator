package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	aksv1 "github.com/rancher/aks-operator/pkg/apis/aks.cattle.io/v1"
	"k8s.io/client-go/rest"
)

func authSpec(mode *string, localAccountsEnabled *bool) *aksv1.AKSClusterConfigSpec {
	return &aksv1.AKSClusterConfigSpec{
		ClusterName:          "test-cluster",
		AuthMode:             mode,
		LocalAccountsEnabled: localAccountsEnabled,
	}
}

func TestUsesEntraTokenFollowsAuthMode(t *testing.T) {
	tests := []struct {
		name               string
		mode               *string
		azureLocalDisabled bool
		want               bool
		why                string
	}{
		{name: "Kubernetes RBAC with local accounts on in Azure", mode: strPtr(aksv1.AuthModeEntraKubernetesRBAC), azureLocalDisabled: false, want: true,
			why: "Entra mode must not fall back to the admin kubeconfig when local accounts are on"},
		{name: "Azure RBAC with local accounts on in Azure", mode: strPtr(aksv1.AuthModeEntraAzureRBAC), azureLocalDisabled: false, want: true},
		{name: "Azure RBAC with local accounts off in Azure", mode: strPtr(aksv1.AuthModeEntraAzureRBAC), azureLocalDisabled: true, want: true},
		{name: "local mode with local accounts on", mode: strPtr(aksv1.AuthModeLocal), azureLocalDisabled: false, want: false},
		{name: "no authMode falls back to Azure, local accounts off", mode: nil, azureLocalDisabled: true, want: true},
		{name: "no authMode falls back to Azure, local accounts on", mode: nil, azureLocalDisabled: false, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := usesEntraToken(authSpec(tc.mode, nil), tc.azureLocalDisabled); got != tc.want {
				t.Fatalf("usesEntraToken = %v, want %v (%s)", got, tc.want, tc.why)
			}
		})
	}
}

func TestValidateLocalAccountsEnabled(t *testing.T) {
	tests := []struct {
		name    string
		mode    *string
		enabled *bool
		wantErr bool
	}{
		{name: "flag omitted for local", mode: strPtr(aksv1.AuthModeLocal)},
		{name: "flag false for local", mode: strPtr(aksv1.AuthModeLocal), enabled: boolPtr(false)},
		{name: "flag true for local", mode: strPtr(aksv1.AuthModeLocal), enabled: boolPtr(true), wantErr: true},
		{name: "flag true with no authMode", mode: nil, enabled: boolPtr(true), wantErr: true},
		{name: "flag true for Kubernetes RBAC", mode: strPtr(aksv1.AuthModeEntraKubernetesRBAC), enabled: boolPtr(true)},
		{name: "flag true for Azure RBAC", mode: strPtr(aksv1.AuthModeEntraAzureRBAC), enabled: boolPtr(true)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLocalAccountsEnabled(authSpec(tc.mode, tc.enabled))
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestAuthSettingsDrift(t *testing.T) {
	entra := strPtr(aksv1.AuthModeEntraAzureRBAC)
	tests := []struct {
		name      string
		config    *aksv1.AKSClusterConfigSpec
		upstream  *aksv1.AKSClusterConfigSpec
		wantDrift bool
	}{
		{name: "matching Entra settings", config: authSpec(entra, boolPtr(true)), upstream: authSpec(entra, boolPtr(true))},
		{name: "local accounts changed in Azure", config: authSpec(entra, boolPtr(false)), upstream: authSpec(entra, boolPtr(true)), wantDrift: true},
		{name: "mode changed in Azure", config: authSpec(entra, nil), upstream: authSpec(strPtr(aksv1.AuthModeEntraKubernetesRBAC), nil), wantDrift: true},
		{name: "local mode ignores the flag", config: authSpec(strPtr(aksv1.AuthModeLocal), nil), upstream: authSpec(strPtr(aksv1.AuthModeLocal), boolPtr(true))},
		{name: "legacy config without authMode is not compared", config: authSpec(nil, nil), upstream: authSpec(entra, boolPtr(true))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := authSettingsDrift(tc.config, tc.upstream)
			if (got != "") != tc.wantDrift {
				t.Fatalf("drift message %q, wantDrift %v", got, tc.wantDrift)
			}
		})
	}
}

// fakeAccessReviewServer answers SelfSubjectAccessReview requests with the given allowed value and records the path.
func fakeAccessReviewServer(t *testing.T, allowed bool) (*httptest.Server, *string) {
	t.Helper()
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.Method + " " + r.URL.Path
		body, _ := io.ReadAll(r.Body)
		var review map[string]interface{}
		if err := json.Unmarshal(body, &review); err != nil {
			t.Errorf("request body is not JSON: %v", err)
		}
		resp := map[string]interface{}{
			"apiVersion": "authorization.k8s.io/v1",
			"kind":       "SelfSubjectAccessReview",
			"status":     map[string]interface{}{"allowed": allowed},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &gotPath
}

func TestSelfSubjectCanListNamespaces(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		srv, gotPath := fakeAccessReviewServer(t, allowed)
		got, err := selfSubjectCanListNamespaces(context.Background(), &rest.Config{Host: srv.URL, BearerToken: "token"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != allowed {
			t.Fatalf("allowed = %v, want %v", got, allowed)
		}
		if *gotPath != "POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			t.Fatalf("unexpected request %q", *gotPath)
		}
	}
}

func TestSelfSubjectCanListNamespacesUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.Close()
	if _, err := selfSubjectCanListNamespaces(context.Background(), &rest.Config{Host: srv.URL}); err == nil {
		t.Fatal("expected an error when the API server is unreachable")
	}
}

func TestKubernetesAccessDeniedMessage(t *testing.T) {
	config := &aksv1.AKSClusterConfig{}
	config.Spec.ClusterName = "test-cluster"
	config.Spec.AADAdminGroupObjectIDs = []string{"group-object-id"}
	config.Name = "c-1"

	msg := kubernetesAccessDeniedMessage(config, testClientID, testPrincipalID)
	for _, want := range []string{
		k8sMessagePrefix,
		testClientID,
		testPrincipalID,
		"group-object-id",
		"az ad group member add --group <admin-group-object-id> --member-id " + testPrincipalID,
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message does not contain %q:\n%s", want, msg)
		}
	}
}

func TestKubernetesAccessDeniedMessageWithoutGroups(t *testing.T) {
	config := &aksv1.AKSClusterConfig{}
	config.Spec.ClusterName = "imported-cluster"
	msg := kubernetesAccessDeniedMessage(config, testClientID, testPrincipalID)
	if !strings.Contains(msg, "<admin-group-object-id>") {
		t.Fatalf("expected a placeholder when no admin group is recorded:\n%s", msg)
	}
}

func boolPtr(b bool) *bool { return &b }
