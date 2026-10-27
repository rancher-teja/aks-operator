package controller

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rancher/aks-operator/pkg/aks"
	aksv1 "github.com/rancher/aks-operator/pkg/apis/aks.cattle.io/v1"
)

const (
	testPrincipalID = "11111111-2222-3333-4444-555555555555"
	testClientID    = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	testRGScope     = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/test-rg"
	testClusterID   = testRGScope + "/providers/Microsoft.ContainerService/managedClusters/test-cluster"
)

func TestShouldAutoAssignClusterAdminRole(t *testing.T) {
	enabled := func(b bool) *bool { return &b }
	tests := []struct {
		name string
		spec aksv1.AKSClusterConfigSpec
		want bool
	}{
		{name: "flag off", spec: aksv1.AKSClusterConfigSpec{AuthMode: strPtr(aksv1.AuthModeEntraAzureRBAC)}, want: false},
		{name: "flag on with Azure RBAC", spec: aksv1.AKSClusterConfigSpec{AuthMode: strPtr(aksv1.AuthModeEntraAzureRBAC), AutoAssignClusterAdminRole: enabled(true)}, want: true},
		{name: "flag on with Kubernetes RBAC", spec: aksv1.AKSClusterConfigSpec{AuthMode: strPtr(aksv1.AuthModeEntraKubernetesRBAC), AutoAssignClusterAdminRole: enabled(true)}, want: false},
		{name: "flag on with local", spec: aksv1.AKSClusterConfigSpec{AuthMode: strPtr(aksv1.AuthModeLocal), AutoAssignClusterAdminRole: enabled(true)}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldAutoAssignClusterAdminRole(&tc.spec); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMissingClusterAdminMessageGivesCommand(t *testing.T) {
	config := &aksv1.AKSClusterConfig{}
	config.Spec.ClusterName = "test-cluster"
	config.Name = "c-1"

	msg := missingClusterAdminMessage(config, testPrincipalID, testClusterID, testClientID)
	for _, want := range []string{
		rbacMessagePrefix,
		testPrincipalID,
		testClientID,
		"az role assignment create --assignee-object-id " + testPrincipalID,
		"--role \"Azure Kubernetes Service RBAC Cluster Admin\"",
		"--scope " + testClusterID,
		"autoAssignClusterAdminRole",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message does not contain %q:\n%s", want, msg)
		}
	}
}

func TestDescribeRoleAssignmentError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantText []string
	}{
		{
			name: "authorization failure names principal, scope and fix",
			err:  &aks.RoleAssignmentError{Action: "create role assignment", Status: 403, Code: "AuthorizationFailed", Message: "no write"},
			wantText: []string{
				"Azure denied the request at [" + testRGScope + "]",
				testPrincipalID,
				testClientID,
				"Grant Owner.",
				"Azure said: no write",
			},
		},
		{
			name: "replication delay says it retries",
			err:  &aks.RoleAssignmentError{Action: "create role assignment", Status: 400, Code: "PrincipalNotFound"},
			wantText: []string{
				"has not finished creating the service principal",
				"retries automatically",
			},
		},
		{
			name: "other Azure refusal shows the code",
			err:  &aks.RoleAssignmentError{Action: "create role assignment", Status: 409, Code: "RoleAssignmentUpdateNotPermitted", Message: "changed"},
			wantText: []string{
				"HTTP 409 RoleAssignmentUpdateNotPermitted",
				"changed",
			},
		},
		{
			name:     "non-Azure error keeps its text",
			err:      fmt.Errorf("token failed"),
			wantText: []string{"token failed", "[" + testRGScope + "]"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := describeRoleAssignmentError(tc.err, "assign the Cluster Admin role", testRGScope, testPrincipalID, testClientID, "Grant Owner.").Error()
			for _, want := range tc.wantText {
				if !strings.Contains(got, want) {
					t.Fatalf("message does not contain %q:\n%s", want, got)
				}
			}
		})
	}
}

func TestDescribeRoleAssignmentErrorUsesHintOnlyForAuthorization(t *testing.T) {
	err := &aks.RoleAssignmentError{Status: 400, Code: "PrincipalNotFound"}
	got := describeRoleAssignmentError(err, "create", testRGScope, testPrincipalID, testClientID, "HINT-TEXT").Error()
	if strings.Contains(got, "HINT-TEXT") {
		t.Fatalf("hint should only appear for authorization failures:\n%s", got)
	}
}

func strPtr(s string) *string { return &s }
