package aks

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const (
	// ClusterAdminRoleDefinitionID is the built-in "Azure Kubernetes Service RBAC Cluster Admin" role.
	ClusterAdminRoleDefinitionID = "b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b"

	roleAssignmentAPIVersion = "2022-04-01"
)

var guidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// namespaceOID is the RFC 4122 namespace used to derive deterministic role assignment names.
var namespaceOID = [16]byte{0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}

type roleAssignmentProperties struct {
	RoleDefinitionID string `json:"roleDefinitionId"`
	PrincipalID      string `json:"principalId"`
	PrincipalType    string `json:"principalType"`
}

type roleAssignmentBody struct {
	Properties roleAssignmentProperties `json:"properties"`
}

// ClusterResourceID returns the ARM resource ID of an AKS managed cluster.
func ClusterResourceID(subscriptionID, resourceGroup, clusterName string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s",
		subscriptionID, resourceGroup, clusterName)
}

// ServicePrincipalObjectID returns the object ID of the identity behind the credential. For client credential
// tokens the oid claim is the service principal's object ID.
func ServicePrincipalObjectID(ctx context.Context, cred azcore.TokenCredential, cfg cloud.Configuration) (string, error) {
	token, err := armToken(ctx, cred, cfg)
	if err != nil {
		return "", err
	}
	return objectIDFromToken(token)
}

// RoleAssignmentName returns a deterministic GUID-formatted name for the cluster admin assignment, so repeated
// reconciliations address the same assignment.
func RoleAssignmentName(scope, principalObjectID string) string {
	return uuidV5(strings.Join([]string{scope, ClusterAdminRoleDefinitionID, principalObjectID}, "|"))
}

// EnsureClusterAdminRoleAssignment creates the cluster admin role assignment at scope for the principal. It returns
// the assignment name and true when the operator created or confirmed it. It returns false without an error when an
// equivalent assignment already exists under another name, since the operator does not own that assignment.
func EnsureClusterAdminRoleAssignment(ctx context.Context, cred azcore.TokenCredential, cfg cloud.Configuration,
	scope, principalObjectID string) (string, bool, error) {
	name := RoleAssignmentName(scope, principalObjectID)
	body := roleAssignmentBody{Properties: roleAssignmentProperties{
		RoleDefinitionID: roleDefinitionID(cfg, scope),
		PrincipalID:      principalObjectID,
		PrincipalType:    "ServicePrincipal",
	}}

	status, respBody, err := armRequest(ctx, cred, cfg, http.MethodPut, roleAssignmentURL(cfg, scope, name), body)
	if err != nil {
		return "", false, err
	}
	switch {
	case status == http.StatusOK || status == http.StatusCreated:
		return name, true, nil
	case status == http.StatusConflict && bytes.Contains(respBody, []byte("RoleAssignmentExists")):
		return "", false, nil
	default:
		return "", false, armError("create cluster admin role assignment", status, respBody)
	}
}

// DeleteClusterAdminRoleAssignment removes an assignment the operator created. A missing assignment is not an error.
func DeleteClusterAdminRoleAssignment(ctx context.Context, cred azcore.TokenCredential, cfg cloud.Configuration,
	scope, name string) error {
	status, respBody, err := armRequest(ctx, cred, cfg, http.MethodDelete, roleAssignmentURL(cfg, scope, name), nil)
	if err != nil {
		return err
	}
	if status == http.StatusOK || status == http.StatusNoContent || status == http.StatusNotFound {
		return nil
	}
	return armError("delete cluster admin role assignment", status, respBody)
}

func roleAssignmentURL(cfg cloud.Configuration, scope, name string) string {
	return fmt.Sprintf("%s%s/providers/Microsoft.Authorization/roleAssignments/%s?api-version=%s",
		armEndpoint(cfg), scope, name, roleAssignmentAPIVersion)
}

// roleDefinitionID returns the full role definition ID for the cluster admin role in the subscription of scope.
func roleDefinitionID(cfg cloud.Configuration, scope string) string {
	subscription := strings.Split(scope, "/")
	subscriptionID := ""
	if len(subscription) > 2 {
		subscriptionID = subscription[2]
	}
	return fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s",
		subscriptionID, ClusterAdminRoleDefinitionID)
}

func armEndpoint(cfg cloud.Configuration) string {
	return strings.TrimSuffix(cfg.Services[cloud.ResourceManager].Endpoint, "/")
}

func armToken(ctx context.Context, cred azcore.TokenCredential, cfg cloud.Configuration) (string, error) {
	svc, ok := cfg.Services[cloud.ResourceManager]
	if !ok {
		return "", fmt.Errorf("cloud configuration has no %s service", cloud.ResourceManager)
	}
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{svc.Audience + "/.default"}})
	if err != nil {
		return "", fmt.Errorf("error acquiring Azure Resource Manager token: %w", err)
	}
	return token.Token, nil
}

func armRequest(ctx context.Context, cred azcore.TokenCredential, cfg cloud.Configuration, method, url string,
	body interface{}) (int, []byte, error) {
	token, err := armToken(ctx, cred, cfg)
	if err != nil {
		return 0, nil, err
	}

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBody, nil
}

func armError(action string, status int, body []byte) error {
	return fmt.Errorf("failed to %s: HTTP %d: %s", action, status, strings.TrimSpace(string(body)))
}

// objectIDFromToken reads the oid claim from an access token issued to the operator's own credential. The token is
// not used to grant access here, so the signature is not verified.
func objectIDFromToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("error decoding access token payload: %w", err)
	}
	var claims struct {
		OID string `json:"oid"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("error parsing access token claims: %w", err)
	}
	if !guidRegex.MatchString(claims.OID) {
		return "", fmt.Errorf("access token has no valid oid claim")
	}
	return claims.OID, nil
}

// uuidV5 returns a name-based (SHA-1) UUID in the RFC 4122 format.
func uuidV5(name string) string {
	h := sha1.New()
	h.Write(namespaceOID[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)

	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
