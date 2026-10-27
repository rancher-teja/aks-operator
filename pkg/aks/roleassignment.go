package aks

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // RFC 4122 version 5 UUIDs are defined with SHA-1. The output is a name, not a secret.
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const (
	// ClusterAdminRoleDefinitionID is the built-in "Azure Kubernetes Service RBAC Cluster Admin" role.
	ClusterAdminRoleDefinitionID = "b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b"

	// RBACAdministratorRoleDefinitionID is the built-in "Role Based Access Control Administrator" role.
	RBACAdministratorRoleDefinitionID = "f58310d9-a9f6-439a-9e8d-f62e7b41a168"

	// RoleAssignmentConditionVersion is the condition version the role assignment API expects for conditions.
	RoleAssignmentConditionVersion = "2.0"

	roleAssignmentAPIVersion = "2022-04-01"
	armRequestTimeout        = 30 * time.Second
)

var guidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// namespaceOID is the RFC 4122 namespace used to derive deterministic role assignment names.
var namespaceOID = [16]byte{0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}

// armHTTPClient has a timeout so a stalled Azure call cannot block a reconcile.
var armHTTPClient = &http.Client{Timeout: armRequestTimeout}

// RoleAssignmentRequest describes one role assignment the operator wants to exist.
type RoleAssignmentRequest struct {
	// Scope is the Azure resource ID the role applies to, such as a resource group or a cluster.
	Scope string
	// RoleDefinitionID is the GUID of the built-in role.
	RoleDefinitionID string
	// PrincipalID is the object ID of the service principal receiving the role.
	PrincipalID string
	// Condition optionally limits what the assignee can do with the role. Empty means no condition.
	Condition string
}

// RoleAssignment is an existing role assignment read back from Azure.
type RoleAssignment struct {
	Name             string
	Scope            string
	RoleDefinitionID string
	PrincipalID      string
	Condition        string
}

// RoleAssignmentError is returned when Azure Resource Manager rejects a role assignment request.
type RoleAssignmentError struct {
	Action  string
	Status  int
	Code    string
	Message string
}

func (e *RoleAssignmentError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("failed to %s: HTTP %d: %s", e.Action, e.Status, e.Message)
	}
	return fmt.Sprintf("failed to %s: HTTP %d %s: %s", e.Action, e.Status, e.Code, e.Message)
}

type roleAssignmentProperties struct {
	RoleDefinitionID string `json:"roleDefinitionId"`
	PrincipalID      string `json:"principalId"`
	PrincipalType    string `json:"principalType"`
	Condition        string `json:"condition,omitempty"`
	ConditionVersion string `json:"conditionVersion,omitempty"`
}

type roleAssignmentBody struct {
	Properties roleAssignmentProperties `json:"properties"`
}

// ClusterResourceID returns the ARM resource ID of an AKS managed cluster.
func ClusterResourceID(subscriptionID, resourceGroup, clusterName string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s",
		subscriptionID, resourceGroup, clusterName)
}

// ResourceGroupID returns the ARM resource ID of a resource group.
func ResourceGroupID(subscriptionID, resourceGroup string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionID, resourceGroup)
}

// SubscriptionID returns the ARM resource ID of a subscription.
func SubscriptionID(subscriptionID string) string {
	return fmt.Sprintf("/subscriptions/%s", subscriptionID)
}

// RBACAdministratorCondition limits a Role Based Access Control Administrator grant. The assignee may assign and
// remove only the Cluster Admin role, and may assign it only to principalObjectID. Every other role assignment write
// or delete is refused.
func RBACAdministratorCondition(principalObjectID string) string {
	return fmt.Sprintf(`(
 (
  !(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})
 )
 OR
 (
  @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {%[1]s}
  AND
  @Request[Microsoft.Authorization/roleAssignments:PrincipalId] ForAnyOfAnyValues:GuidEquals {%[2]s}
 )
)
AND
(
 (
  !(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})
 )
 OR
 (
  @Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {%[1]s}
 )
)`, ClusterAdminRoleDefinitionID, principalObjectID)
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

// RoleAssignmentName returns a deterministic GUID-formatted name for a role assignment, so repeated reconciliations
// address the same assignment. The condition is not part of the name, so changing a condition is refused by Azure
// rather than silently creating a second assignment.
func RoleAssignmentName(scope, roleDefinitionID, principalObjectID string) string {
	return uuidV5(strings.Join([]string{scope, roleDefinitionID, principalObjectID}, "|"))
}

// EnsureRoleAssignment creates the role assignment described by req. It returns the assignment name and true when the
// operator created it. It returns false without an error when an equivalent assignment already exists under another
// name, since the operator does not own that assignment.
func EnsureRoleAssignment(ctx context.Context, cred azcore.TokenCredential, cfg cloud.Configuration,
	req RoleAssignmentRequest) (string, bool, error) {
	name := RoleAssignmentName(req.Scope, req.RoleDefinitionID, req.PrincipalID)
	props := roleAssignmentProperties{
		RoleDefinitionID: fullRoleDefinitionID(req.Scope, req.RoleDefinitionID),
		PrincipalID:      req.PrincipalID,
		PrincipalType:    "ServicePrincipal",
	}
	if req.Condition != "" {
		props.Condition = req.Condition
		props.ConditionVersion = RoleAssignmentConditionVersion
	}

	status, respBody, err := armRequest(ctx, cred, cfg, http.MethodPut,
		roleAssignmentURL(cfg, req.Scope, name), roleAssignmentBody{Properties: props})
	if err != nil {
		return "", false, err
	}
	switch {
	case status == http.StatusOK || status == http.StatusCreated:
		return name, true, nil
	case status == http.StatusConflict && bytes.Contains(respBody, []byte("RoleAssignmentExists")):
		return "", false, nil
	default:
		return "", false, newRoleAssignmentError("create role assignment", status, respBody)
	}
}

// DeleteRoleAssignment removes an assignment the operator created. A missing assignment is not an error.
func DeleteRoleAssignment(ctx context.Context, cred azcore.TokenCredential, cfg cloud.Configuration,
	scope, name string) error {
	status, respBody, err := armRequest(ctx, cred, cfg, http.MethodDelete, roleAssignmentURL(cfg, scope, name), nil)
	if err != nil {
		return err
	}
	if status == http.StatusOK || status == http.StatusNoContent || status == http.StatusNotFound {
		return nil
	}
	return newRoleAssignmentError("delete role assignment", status, respBody)
}

// ListRoleAssignments returns the role assignments for principalObjectID at scope and below it. Azure returns
// assignments on the principal across all pages, so every page is read.
func ListRoleAssignments(ctx context.Context, cred azcore.TokenCredential, cfg cloud.Configuration,
	scope, principalObjectID string) ([]RoleAssignment, error) {
	query := url.Values{
		"api-version": {roleAssignmentAPIVersion},
		"$filter":     {fmt.Sprintf("assignedTo('%s')", principalObjectID)},
	}
	next := armEndpoint(cfg) + scope + "/providers/Microsoft.Authorization/roleAssignments?" + query.Encode()

	var all []RoleAssignment
	for next != "" {
		status, body, err := armRequest(ctx, cred, cfg, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, newRoleAssignmentError("list role assignments", status, body)
		}

		var page struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					Scope            string `json:"scope"`
					RoleDefinitionID string `json:"roleDefinitionId"`
					PrincipalID      string `json:"principalId"`
					Condition        string `json:"condition"`
				} `json:"properties"`
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("error parsing role assignments: %w", err)
		}
		for _, v := range page.Value {
			all = append(all, RoleAssignment{
				Name:             v.Name,
				Scope:            v.Properties.Scope,
				RoleDefinitionID: v.Properties.RoleDefinitionID,
				PrincipalID:      v.Properties.PrincipalID,
				Condition:        v.Properties.Condition,
			})
		}
		next = page.NextLink
	}
	return all, nil
}

// AssignmentsAtOrAbove returns the assignments of roleDefinitionID that apply to scope. An assignment applies when it
// is made at scope or at a parent of scope, because Azure inherits roles down the resource hierarchy.
func AssignmentsAtOrAbove(assignments []RoleAssignment, scope, roleDefinitionID string) []RoleAssignment {
	var matches []RoleAssignment
	target := strings.ToLower(scope)
	for _, a := range assignments {
		if !roleDefinitionMatches(a.RoleDefinitionID, roleDefinitionID) {
			continue
		}
		assigned := strings.ToLower(strings.TrimSuffix(a.Scope, "/"))
		if target == assigned || strings.HasPrefix(target, assigned+"/") {
			matches = append(matches, a)
		}
	}
	return matches
}

func roleDefinitionMatches(fullID, roleDefinitionID string) bool {
	return strings.HasSuffix(strings.ToLower(fullID), "/roledefinitions/"+strings.ToLower(roleDefinitionID))
}

func roleAssignmentURL(cfg cloud.Configuration, scope, name string) string {
	return fmt.Sprintf("%s%s/providers/Microsoft.Authorization/roleAssignments/%s?api-version=%s",
		armEndpoint(cfg), scope, name, roleAssignmentAPIVersion)
}

// fullRoleDefinitionID returns the full role definition ID for a built-in role in the subscription of scope.
func fullRoleDefinitionID(scope, roleDefinitionID string) string {
	subscription := strings.Split(scope, "/")
	subscriptionID := ""
	if len(subscription) > 2 {
		subscriptionID = subscription[2]
	}
	return fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s",
		subscriptionID, roleDefinitionID)
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

	resp, err := armHTTPClient.Do(req)
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

// newRoleAssignmentError builds a RoleAssignmentError from an Azure error response body.
func newRoleAssignmentError(action string, status int, body []byte) *RoleAssignmentError {
	var parsed struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	message := strings.TrimSpace(string(body))
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.Error.Code != "" {
		return &RoleAssignmentError{Action: action, Status: status, Code: parsed.Error.Code, Message: parsed.Error.Message}
	}
	return &RoleAssignmentError{Action: action, Status: status, Message: message}
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
	h := sha1.New() //nolint:gosec // RFC 4122 version 5 name derivation, not a security control.
	h.Write(namespaceOID[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)

	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
