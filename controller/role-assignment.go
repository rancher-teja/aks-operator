package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v5"
	"github.com/rancher/aks-operator/pkg/aks"
	aksv1 "github.com/rancher/aks-operator/pkg/apis/aks.cattle.io/v1"
	"github.com/sirupsen/logrus"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// rbacMessagePrefix starts every status message about Azure RBAC access, so the operator can clear its own message
// without touching messages written by other reconcile steps.
const rbacMessagePrefix = "Azure RBAC access: "

// k8sMessagePrefix starts status messages about Kubernetes RBAC access for entraKubernetesRBAC clusters.
const k8sMessagePrefix = "Kubernetes RBAC access: "

// shouldAutoAssignClusterAdminRole reports whether the operator should create role assignments itself.
func shouldAutoAssignClusterAdminRole(spec *aksv1.AKSClusterConfigSpec) bool {
	return aks.Bool(spec.AutoAssignClusterAdminRole) && aks.String(spec.AuthMode) == aksv1.AuthModeEntraAzureRBAC
}

// ensureAzureRBACAccess checks the Azure RBAC requirements of an entraAzureRBAC cluster. When
// autoAssignClusterAdminRole is set, it grants the service principal the access Rancher needs. When it is not set,
// it only reports what is missing in the status message, so an administrator can grant it by hand.
func (h *Handler) ensureAzureRBACAccess(ctx context.Context, config *aksv1.AKSClusterConfig,
	cluster *armcontainerservice.ManagedCluster) (*aksv1.AKSClusterConfig, error) {
	if aks.String(config.Spec.AuthMode) != aksv1.AuthModeEntraAzureRBAC {
		return config, nil
	}
	if cluster.Properties == nil || cluster.Properties.AADProfile == nil || !aks.Bool(cluster.Properties.AADProfile.EnableAzureRBAC) {
		return config, fmt.Errorf("cluster [%s (id: %s)] does not have Azure RBAC enabled, which authMode %s requires. "+
			"Azure RBAC can only be turned on when a cluster is created, so the cluster must be recreated with authMode %s",
			config.Spec.ClusterName, config.Name, aksv1.AuthModeEntraAzureRBAC, aksv1.AuthModeEntraAzureRBAC)
	}

	principalID, err := aks.ServicePrincipalObjectID(ctx, h.azureClients.tokenCredential, h.azureClients.credentials.Cloud)
	if err != nil {
		return config, fmt.Errorf("cannot sign in as the cloud credential's service principal (client ID %s) for cluster [%s (id: %s)]: %w. "+
			"Check that the client secret is valid and has not expired",
			h.azureClients.credentials.ClientID, config.Spec.ClusterName, config.Name, err)
	}
	logrus.Infof("Service principal object ID for cluster [%s (id: %s)] is [%s]. To compare with the client ID, run: az ad sp show --id %s --query id -o tsv",
		config.Spec.ClusterName, config.Name, principalID, h.azureClients.credentials.ClientID)

	clusterScope := aks.ClusterResourceID(h.azureClients.credentials.SubscriptionID, config.Spec.ResourceGroup, config.Spec.ClusterName)
	if !shouldAutoAssignClusterAdminRole(&config.Spec) {
		return h.reportClusterAdminAccess(ctx, config, principalID, clusterScope)
	}
	return h.autoAssignClusterAdminAccess(ctx, config, principalID, clusterScope)
}

// reportClusterAdminAccess records in the status whether the service principal already has the Cluster Admin role on
// the cluster. It never blocks the cluster, because an administrator may grant the role after the cluster is created.
func (h *Handler) reportClusterAdminAccess(ctx context.Context, config *aksv1.AKSClusterConfig, principalID, clusterScope string) (*aksv1.AKSClusterConfig, error) {
	assignments, err := aks.ListRoleAssignments(ctx, h.azureClients.tokenCredential, h.azureClients.credentials.Cloud,
		aks.SubscriptionID(h.azureClients.credentials.SubscriptionID), principalID)
	if err != nil {
		return h.recordRBACStatus(config, "", fmt.Sprintf("%scould not read role assignments for cluster [%s (id: %s)]: %s. "+
			"Grant the service principal Reader on the subscription so the operator can check Cluster Admin access.",
			rbacMessagePrefix, config.Spec.ClusterName, config.Name, err))
	}
	if len(aks.AssignmentsAtOrAbove(assignments, clusterScope, aks.ClusterAdminRoleDefinitionID)) > 0 {
		return h.recordRBACStatus(config, "", "")
	}
	return h.recordRBACStatus(config, "", missingClusterAdminMessage(config, principalID, clusterScope, h.azureClients.credentials.ClientID))
}

// autoAssignClusterAdminAccess grants the service principal the Cluster Admin role on the cluster. It first grants
// Role Based Access Control Administrator on the resource group, limited by a condition, so the grant works for
// clusters created after the first one. The condition is set on the grant, not on this request.
func (h *Handler) autoAssignClusterAdminAccess(ctx context.Context, config *aksv1.AKSClusterConfig, principalID, clusterScope string) (*aksv1.AKSClusterConfig, error) {
	cloudCfg := h.azureClients.credentials.Cloud
	clientID := h.azureClients.credentials.ClientID
	rgScope := aks.ResourceGroupID(h.azureClients.credentials.SubscriptionID, config.Spec.ResourceGroup)

	// Existing assignments are read first, so a steady-state reconcile makes no writes. If the read fails, the writes
	// below still run, and Azure's idempotent PUT covers the existing assignments.
	assignments, err := aks.ListRoleAssignments(ctx, h.azureClients.tokenCredential, cloudCfg, rgScope, principalID)
	if err != nil {
		logrus.Warnf("Could not read existing role assignments at [%s]: %v. Continuing with the grants.", rgScope, err)
	}

	if len(aks.AssignmentsAtOrAbove(assignments, rgScope, aks.RBACAdministratorRoleDefinitionID)) == 0 {
		_, owned, err := aks.EnsureRoleAssignment(ctx, h.azureClients.tokenCredential, cloudCfg, aks.RoleAssignmentRequest{
			Scope:            rgScope,
			RoleDefinitionID: aks.RBACAdministratorRoleDefinitionID,
			PrincipalID:      principalID,
			Condition:        aks.RBACAdministratorCondition(principalID),
		})
		if err != nil {
			return config, describeRoleAssignmentError(err,
				"grant the Role Based Access Control Administrator bootstrap role", rgScope, principalID, clientID,
				"This one-time grant needs Owner or User Access Administrator on the resource group.")
		}
		if owned {
			logrus.Infof("Granted Role Based Access Control Administrator at [%s] to object ID [%s], limited to the Cluster Admin role", rgScope, principalID)
		}
	}

	clusterAdminName := aks.RoleAssignmentName(clusterScope, aks.ClusterAdminRoleDefinitionID, principalID)
	if hasAssignmentNamed(assignments, clusterScope, clusterAdminName) {
		return h.recordRBACStatus(config, clusterAdminName, "")
	}

	name, owned, err := aks.EnsureRoleAssignment(ctx, h.azureClients.tokenCredential, cloudCfg, aks.RoleAssignmentRequest{
		Scope:            clusterScope,
		RoleDefinitionID: aks.ClusterAdminRoleDefinitionID,
		PrincipalID:      principalID,
	})
	if err != nil {
		return config, describeRoleAssignmentError(err, "assign the Cluster Admin role", clusterScope, principalID, clientID,
			"Check that the Role Based Access Control Administrator grant on the resource group still exists and its condition has not changed.")
	}
	if !owned {
		logrus.Warnf("An equivalent Cluster Admin role assignment already exists on cluster [%s (id: %s)] and was not created by the operator. The operator will not delete it.", config.Spec.ClusterName, config.Name)
		return h.recordRBACStatus(config, "", "")
	}
	return h.recordRBACStatus(config, name, "")
}

// hasAssignmentNamed reports whether an assignment with the given name exists at scope. The name is deterministic, so
// a match means the operator created the assignment.
func hasAssignmentNamed(assignments []aks.RoleAssignment, scope, name string) bool {
	for _, a := range assignments {
		if strings.EqualFold(a.Name, name) && strings.EqualFold(strings.TrimSuffix(a.Scope, "/"), scope) {
			return true
		}
	}
	return false
}

// removeClusterAdminRoleAssignment deletes the Cluster Admin role assignment the operator created for the cluster.
// Assignments the operator did not create are never touched. The resource group grant is shared by other clusters,
// so it is left in place.
func (h *Handler) removeClusterAdminRoleAssignment(ctx context.Context, config *aksv1.AKSClusterConfig) error {
	name := config.Status.ClusterAdminRoleAssignmentName
	if name == "" {
		return nil
	}
	scope := aks.ClusterResourceID(h.azureClients.credentials.SubscriptionID, config.Spec.ResourceGroup, config.Spec.ClusterName)
	return aks.DeleteRoleAssignment(ctx, h.azureClients.tokenCredential, h.azureClients.credentials.Cloud, scope, name)
}

// recordRBACStatus stores the assignment name the operator created and the RBAC status message. An empty message
// clears only a message the operator wrote earlier. It persists the status only when something changed.
func (h *Handler) recordRBACStatus(config *aksv1.AKSClusterConfig, assignmentName, message string) (*aksv1.AKSClusterConfig, error) {
	newMessage := config.Status.Message
	switch {
	case message != "":
		newMessage = message
	case strings.HasPrefix(config.Status.Message, rbacMessagePrefix), strings.HasPrefix(config.Status.Message, k8sMessagePrefix):
		newMessage = ""
	}
	newName := config.Status.ClusterAdminRoleAssignmentName
	if assignmentName != "" {
		newName = assignmentName
	}
	if newMessage == config.Status.Message && newName == config.Status.ClusterAdminRoleAssignmentName {
		return config, nil
	}

	config = config.DeepCopy()
	config.Status.Message = newMessage
	config.Status.ClusterAdminRoleAssignmentName = newName
	return h.aksCC.UpdateStatus(config)
}

// missingClusterAdminMessage explains how to grant the Cluster Admin role by hand.
func missingClusterAdminMessage(config *aksv1.AKSClusterConfig, principalID, clusterScope, clientID string) string {
	return fmt.Sprintf("%scluster [%s (id: %s)] does not grant the service principal (client ID %s, object ID %s) the "+
		"Azure Kubernetes Service RBAC Cluster Admin role. Rancher cannot create its service account until it has the role. "+
		"Grant it with: az role assignment create --assignee-object-id %s --assignee-principal-type ServicePrincipal "+
		"--role \"Azure Kubernetes Service RBAC Cluster Admin\" --scope %s. "+
		"Or set autoAssignClusterAdminRole to true once the resource group grant is in place.",
		rbacMessagePrefix, config.Spec.ClusterName, config.Name, clientID, principalID, principalID, clusterScope)
}

// describeRoleAssignmentError turns an Azure role assignment error into a message that names the principal, the scope,
// and the next step. Other errors are returned with the action and scope added.
func describeRoleAssignmentError(err error, action, scope, principalID, clientID, hint string) error {
	var raErr *aks.RoleAssignmentError
	if !errors.As(err, &raErr) {
		return fmt.Errorf("error trying to %s at [%s]: %w", action, scope, err)
	}

	switch {
	case raErr.Status == http.StatusForbidden:
		return fmt.Errorf("%s%s: Azure denied the request at [%s]. The service principal (client ID %s, object ID %s) "+
			"cannot write role assignments at this scope. %s Azure said: %s",
			rbacMessagePrefix, action, scope, clientID, principalID, hint, raErr.Message)
	case raErr.Code == "PrincipalNotFound":
		return fmt.Errorf("%sAzure has not finished creating the service principal (object ID %s), so it cannot %s yet. "+
			"The operator retries automatically",
			rbacMessagePrefix, principalID, action)
	default:
		return fmt.Errorf("%sAzure refused to %s at [%s] (HTTP %d %s): %s",
			rbacMessagePrefix, action, scope, raErr.Status, raErr.Code, raErr.Message)
	}
}

// checkKubernetesRBACAccess asks the cluster whether the cloud credential's service principal may list namespaces. It
// signs in with the principal's own Entra ID token, so it needs no extra Azure permission. A denied answer usually means
// the principal is not in the Entra admin group. The status message then gives the command to add it. The check never
// blocks the cluster.
func (h *Handler) checkKubernetesRBACAccess(ctx context.Context, config *aksv1.AKSClusterConfig) (*aksv1.AKSClusterConfig, error) {
	if aks.String(config.Spec.AuthMode) != aksv1.AuthModeEntraKubernetesRBAC {
		return config, nil
	}
	clientID := h.azureClients.credentials.ClientID

	restConfig, err := h.getEntraClusterKubeConfig(ctx, &config.Spec)
	if err != nil {
		return h.recordRBACStatus(config, "", fmt.Sprintf("%scould not build a sign-in for cluster [%s (id: %s)]: %s",
			k8sMessagePrefix, config.Spec.ClusterName, config.Name, err))
	}
	allowed, err := selfSubjectCanListNamespaces(ctx, restConfig)
	if err != nil {
		return h.recordRBACStatus(config, "", fmt.Sprintf("%scould not check access on cluster [%s (id: %s)]: %s",
			k8sMessagePrefix, config.Spec.ClusterName, config.Name, err))
	}
	if allowed {
		return h.recordRBACStatus(config, "", "")
	}

	principalID, err := aks.ServicePrincipalObjectID(ctx, h.azureClients.tokenCredential, h.azureClients.credentials.Cloud)
	if err != nil {
		return h.recordRBACStatus(config, "", fmt.Sprintf("%sthe service principal was denied on cluster [%s (id: %s)] and its object ID could not be read: %s",
			k8sMessagePrefix, config.Spec.ClusterName, config.Name, err))
	}
	return h.recordRBACStatus(config, "", kubernetesAccessDeniedMessage(config, clientID, principalID))
}

// selfSubjectCanListNamespaces asks the API server whether the caller may list namespaces, using a
// SelfSubjectAccessReview. The caller is the identity in restConfig.
func selfSubjectCanListNamespaces(ctx context.Context, restConfig *rest.Config) (bool, error) {
	jsonConfig := rest.CopyConfig(restConfig)
	jsonConfig.ContentType = "application/json"
	clientset, err := kubernetes.NewForConfig(jsonConfig)
	if err != nil {
		return false, err
	}
	review, err := clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: "list", Resource: "namespaces"},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return review.Status.Allowed, nil
}

// kubernetesAccessDeniedMessage explains that the service principal was denied, and how to add it to the admin group.
func kubernetesAccessDeniedMessage(config *aksv1.AKSClusterConfig, clientID, principalID string) string {
	groups := strings.Join(config.Spec.AADAdminGroupObjectIDs, ", ")
	if groups == "" {
		groups = "<admin-group-object-id>"
	}
	return fmt.Sprintf("%scluster [%s (id: %s)] denied the service principal (client ID %s, object ID %s) "+
		"access to list namespaces. Add the service principal to the Entra admin group (%s) with: "+
		"az ad group member add --group <admin-group-object-id> --member-id %s. Then wait a few minutes for the change to apply.",
		k8sMessagePrefix, config.Spec.ClusterName, config.Name, clientID, principalID, groups, principalID)
}
