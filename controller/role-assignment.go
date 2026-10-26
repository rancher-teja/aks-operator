package controller

import (
	"context"
	"fmt"

	"github.com/rancher/aks-operator/pkg/aks"
	aksv1 "github.com/rancher/aks-operator/pkg/apis/aks.cattle.io/v1"
	"github.com/sirupsen/logrus"
)

// shouldAutoAssignClusterAdminRole reports whether the operator should assign the cluster admin role itself.
func shouldAutoAssignClusterAdminRole(spec *aksv1.AKSClusterConfigSpec) bool {
	return aks.Bool(spec.AutoAssignClusterAdminRole) && aks.String(spec.AuthMode) == aksv1.AuthModeEntraAzureRBAC
}

// ensureClusterAdminRoleAssignment assigns the Cluster Admin role to the cloud credential's service principal at the
// cluster scope. It returns a copy of config with the assignment name recorded only when the operator created it.
func (h *Handler) ensureClusterAdminRoleAssignment(ctx context.Context, config *aksv1.AKSClusterConfig) (*aksv1.AKSClusterConfig, error) {
	if !shouldAutoAssignClusterAdminRole(&config.Spec) {
		return config, nil
	}

	cloudCfg := h.azureClients.credentials.Cloud
	clientID := h.azureClients.credentials.ClientID

	principalID, err := aks.ServicePrincipalObjectID(ctx, h.azureClients.tokenCredential, cloudCfg)
	if err != nil {
		return config, fmt.Errorf("error getting service principal object ID for cluster [%s (id: %s)]: %w", config.Spec.ClusterName, config.Name, err)
	}
	logrus.Infof("Assigning the Cluster Admin role to service principal object ID [%s] on cluster [%s (id: %s)]. To compare with the client ID, run: az ad sp show --id %s --query id -o tsv",
		principalID, config.Spec.ClusterName, config.Name, clientID)

	scope := aks.ClusterResourceID(h.azureClients.credentials.SubscriptionID, config.Spec.ResourceGroup, config.Spec.ClusterName)
	name, owned, err := aks.EnsureClusterAdminRoleAssignment(ctx, h.azureClients.tokenCredential, cloudCfg, scope, principalID)
	if err != nil {
		return config, fmt.Errorf("error assigning cluster admin role for cluster [%s (id: %s)]: %w", config.Spec.ClusterName, config.Name, err)
	}
	if !owned {
		logrus.Warnf("An equivalent Cluster Admin role assignment already exists on cluster [%s (id: %s)] and was not created by the operator. The operator will not delete it.", config.Spec.ClusterName, config.Name)
		return config, nil
	}

	if config.Status.ClusterAdminRoleAssignmentName == name {
		return config, nil
	}
	config = config.DeepCopy()
	config.Status.ClusterAdminRoleAssignmentName = name
	return config, nil
}

// removeClusterAdminRoleAssignment deletes the Cluster Admin role assignment the operator created for the cluster.
// Assignments the operator did not create are never touched.
func (h *Handler) removeClusterAdminRoleAssignment(ctx context.Context, config *aksv1.AKSClusterConfig) error {
	name := config.Status.ClusterAdminRoleAssignmentName
	if name == "" {
		return nil
	}
	scope := aks.ClusterResourceID(h.azureClients.credentials.SubscriptionID, config.Spec.ResourceGroup, config.Spec.ClusterName)
	return aks.DeleteClusterAdminRoleAssignment(ctx, h.azureClients.tokenCredential, h.azureClients.credentials.Cloud, scope, name)
}
