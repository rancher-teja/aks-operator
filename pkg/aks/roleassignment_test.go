package aks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const (
	testOID         = "11111111-2222-3333-4444-555555555555"
	testSubscriptio = "00000000-0000-0000-0000-000000000001"
	testScope       = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/test-rg/providers/Microsoft.ContainerService/managedClusters/test-cluster"
	testRGScope     = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/test-rg"
	testToken       = "test-access-token"
)

var guidFormat = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type fakeTokenCredential struct {
	token string
	err   error
}

func (f fakeTokenCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: f.token, ExpiresOn: time.Now().Add(time.Hour)}, f.err
}

// jwtWithClaims builds an unsigned JWT with the given payload claims.
func jwtWithClaims(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func armConfig(endpoint string) cloud.Configuration {
	return cloud.Configuration{
		Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Audience: "https://management.azure.com/", Endpoint: endpoint},
		},
	}
}

func TestObjectIDFromToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		want    string
		wantErr bool
	}{
		{name: "valid oid", token: jwtWithClaims(t, map[string]interface{}{"oid": testOID}), want: testOID},
		{name: "missing oid", token: jwtWithClaims(t, map[string]interface{}{"appid": testOID}), wantErr: true},
		{name: "oid is not a GUID", token: jwtWithClaims(t, map[string]interface{}{"oid": "not-a-guid"}), wantErr: true},
		{name: "not a JWT", token: "opaque-token", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := objectIDFromToken(tc.token)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRoleAssignmentNameIsDeterministic(t *testing.T) {
	first := RoleAssignmentName(testScope, ClusterAdminRoleDefinitionID, testOID)
	second := RoleAssignmentName(testScope, ClusterAdminRoleDefinitionID, testOID)
	if first != second {
		t.Fatalf("name changed between calls: %q and %q", first, second)
	}
	if !guidFormat.MatchString(first) {
		t.Fatalf("name %q is not a version 5 GUID", first)
	}
	if other := RoleAssignmentName(testScope, ClusterAdminRoleDefinitionID, "99999999-2222-3333-4444-555555555555"); other == first {
		t.Fatalf("different principals produced the same name %q", first)
	}
	if other := RoleAssignmentName(testScope, RBACAdministratorRoleDefinitionID, testOID); other == first {
		t.Fatalf("different roles produced the same name %q", first)
	}
}

func TestEnsureRoleAssignmentCreatesClusterAdmin(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	var gotBody map[string]map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path+"?"+r.URL.RawQuery, r.Header.Get("Authorization")
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &gotBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	cred := fakeTokenCredential{token: testToken}
	name, owned, err := EnsureRoleAssignment(context.Background(), cred, armConfig(srv.URL), RoleAssignmentRequest{
		Scope:            testScope,
		RoleDefinitionID: ClusterAdminRoleDefinitionID,
		PrincipalID:      testOID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !owned {
		t.Fatal("expected the operator to own the created assignment")
	}
	if name != RoleAssignmentName(testScope, ClusterAdminRoleDefinitionID, testOID) {
		t.Fatalf("name %q does not match the deterministic name", name)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("method %s, want PUT", gotMethod)
	}
	wantPath := testScope + "/providers/Microsoft.Authorization/roleAssignments/" + name + "?api-version=2022-04-01"
	if gotPath != wantPath {
		t.Fatalf("path %q, want %q", gotPath, wantPath)
	}
	if gotAuth != "Bearer "+testToken {
		t.Fatalf("authorization header %q", gotAuth)
	}
	props := gotBody["properties"]
	if props["principalId"] != testOID || props["principalType"] != "ServicePrincipal" {
		t.Fatalf("unexpected principal in body: %v", props)
	}
	if !strings.HasSuffix(props["roleDefinitionId"], "/providers/Microsoft.Authorization/roleDefinitions/"+ClusterAdminRoleDefinitionID) {
		t.Fatalf("unexpected role definition %q", props["roleDefinitionId"])
	}
	if !strings.Contains(props["roleDefinitionId"], "/subscriptions/"+testSubscriptio+"/") {
		t.Fatalf("role definition %q is not in the cluster subscription", props["roleDefinitionId"])
	}
	if _, ok := props["condition"]; ok {
		t.Fatalf("unconditioned assignment must not carry a condition: %v", props)
	}
}

func TestEnsureRoleAssignmentSendsCondition(t *testing.T) {
	var gotProps map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Properties map[string]string `json:"properties"`
		}
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &body)
		gotProps = body.Properties
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	condition := RBACAdministratorCondition(testOID)
	_, owned, err := EnsureRoleAssignment(context.Background(), fakeTokenCredential{token: testToken}, armConfig(srv.URL), RoleAssignmentRequest{
		Scope:            testRGScope,
		RoleDefinitionID: RBACAdministratorRoleDefinitionID,
		PrincipalID:      testOID,
		Condition:        condition,
	})
	if err != nil || !owned {
		t.Fatalf("owned=%v err=%v", owned, err)
	}
	if !strings.HasSuffix(gotProps["roleDefinitionId"], "/roleDefinitions/"+RBACAdministratorRoleDefinitionID) {
		t.Fatalf("expected the RBAC Administrator role, got %q", gotProps["roleDefinitionId"])
	}
	if gotProps["condition"] != condition {
		t.Fatalf("condition not sent as given")
	}
	if gotProps["conditionVersion"] != RoleAssignmentConditionVersion {
		t.Fatalf("conditionVersion %q, want %q", gotProps["conditionVersion"], RoleAssignmentConditionVersion)
	}
}

func TestRBACAdministratorConditionLimitsRoleAndPrincipal(t *testing.T) {
	condition := RBACAdministratorCondition(testOID)
	for _, want := range []string{
		ClusterAdminRoleDefinitionID,
		testOID,
		"Microsoft.Authorization/roleAssignments/write",
		"Microsoft.Authorization/roleAssignments/delete",
	} {
		if !strings.Contains(condition, want) {
			t.Fatalf("condition does not mention %q:\n%s", want, condition)
		}
	}
	if strings.Contains(condition, "f58310d9-a9f6-439a-9e8d-f62e7b41a168") {
		t.Fatal("condition must not allow assigning the RBAC Administrator role itself")
	}
}

func TestEnsureRoleAssignmentExistingEquivalent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"RoleAssignmentExists","message":"exists"}}`))
	}))
	defer srv.Close()

	_, owned, err := EnsureRoleAssignment(context.Background(), fakeTokenCredential{token: testToken}, armConfig(srv.URL), RoleAssignmentRequest{
		Scope: testScope, RoleDefinitionID: ClusterAdminRoleDefinitionID, PrincipalID: testOID,
	})
	if err != nil {
		t.Fatalf("an existing equivalent assignment should not be an error: %v", err)
	}
	if owned {
		t.Fatal("an assignment created outside the operator must not be marked as owned")
	}
}

func TestEnsureRoleAssignmentFailures(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantCode string
	}{
		{name: "transient throttling", status: http.StatusTooManyRequests, body: `{"error":{"code":"TooManyRequests"}}`, wantCode: "TooManyRequests"},
		{name: "server error", status: http.StatusInternalServerError, body: `{"error":{"code":"InternalError"}}`, wantCode: "InternalError"},
		{name: "authorization failure", status: http.StatusForbidden, body: `{"error":{"code":"AuthorizationFailed","message":"no write"}}`, wantCode: "AuthorizationFailed"},
		{name: "principal not yet replicated", status: http.StatusBadRequest, body: `{"error":{"code":"PrincipalNotFound"}}`, wantCode: "PrincipalNotFound"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, owned, err := EnsureRoleAssignment(context.Background(), fakeTokenCredential{token: testToken}, armConfig(srv.URL), RoleAssignmentRequest{
				Scope: testScope, RoleDefinitionID: ClusterAdminRoleDefinitionID, PrincipalID: testOID,
			})
			if err == nil {
				t.Fatal("expected an error so the caller can retry or report it")
			}
			if owned {
				t.Fatal("a failed request must not be marked as owned")
			}
			var raErr *RoleAssignmentError
			if !errors.As(err, &raErr) {
				t.Fatalf("expected *RoleAssignmentError, got %T", err)
			}
			if raErr.Status != tc.status || raErr.Code != tc.wantCode {
				t.Fatalf("status %d code %q, want %d %q", raErr.Status, raErr.Code, tc.status, tc.wantCode)
			}
		})
	}
}

func TestEnsureRoleAssignmentTokenFailure(t *testing.T) {
	cred := fakeTokenCredential{err: context.DeadlineExceeded}
	_, _, err := EnsureRoleAssignment(context.Background(), cred, armConfig("http://unused"), RoleAssignmentRequest{
		Scope: testScope, RoleDefinitionID: ClusterAdminRoleDefinitionID, PrincipalID: testOID,
	})
	if err == nil {
		t.Fatal("expected a token error to be returned")
	}
}

func TestServicePrincipalObjectID(t *testing.T) {
	cred := fakeTokenCredential{token: jwtWithClaims(t, map[string]interface{}{"oid": testOID})}
	got, err := ServicePrincipalObjectID(context.Background(), cred, armConfig("http://unused"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testOID {
		t.Fatalf("got %q, want %q", got, testOID)
	}
}

func TestDeleteRoleAssignment(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{name: "deleted", status: http.StatusOK},
		{name: "already absent", status: http.StatusNotFound},
		{name: "authorization failure", status: http.StatusForbidden, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("method %s, want DELETE", r.Method)
				}
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			err := DeleteRoleAssignment(context.Background(), fakeTokenCredential{token: testToken}, armConfig(srv.URL), testScope, "name")
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestListRoleAssignmentsReadsAllPages(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(`{"value":[{"name":"b","properties":{"scope":"` + testRGScope + `","roleDefinitionId":"/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/` + ClusterAdminRoleDefinitionID + `","principalId":"` + testOID + `"}}]}`))
			return
		}
		if r.URL.Query().Get("$filter") != fmt.Sprintf("assignedTo('%s')", testOID) {
			t.Errorf("unexpected filter %q", r.URL.Query().Get("$filter"))
		}
		next := srv.URL + r.URL.Path + "?page=2"
		_, _ = w.Write([]byte(`{"value":[{"name":"a","properties":{"scope":"` + testScope + `","roleDefinitionId":"/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/` + RBACAdministratorRoleDefinitionID + `","principalId":"` + testOID + `","condition":"c"}}],"nextLink":"` + next + `"}`))
	}))
	defer srv.Close()

	got, err := ListRoleAssignments(context.Background(), fakeTokenCredential{token: testToken}, armConfig(srv.URL), testRGScope, testOID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d assignments, want 2 from both pages", len(got))
	}
	if got[0].Condition != "c" {
		t.Fatalf("condition not read back: %+v", got[0])
	}
}

func TestListRoleAssignmentsForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed","message":"no read"}}`))
	}))
	defer srv.Close()

	_, err := ListRoleAssignments(context.Background(), fakeTokenCredential{token: testToken}, armConfig(srv.URL), testRGScope, testOID)
	var raErr *RoleAssignmentError
	if !errors.As(err, &raErr) || raErr.Status != http.StatusForbidden {
		t.Fatalf("expected a 403 RoleAssignmentError, got %v", err)
	}
}

func TestAssignmentsAtOrAbove(t *testing.T) {
	clusterAdmin := "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/" + ClusterAdminRoleDefinitionID
	owner := "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	assignments := []RoleAssignment{
		{Scope: testRGScope, RoleDefinitionID: clusterAdmin},
		{Scope: testScope, RoleDefinitionID: clusterAdmin},
		{Scope: testRGScope + "-other", RoleDefinitionID: clusterAdmin},
		{Scope: "/subscriptions/" + testSubscriptio, RoleDefinitionID: owner},
	}

	if got := AssignmentsAtOrAbove(assignments, testScope, ClusterAdminRoleDefinitionID); len(got) != 2 {
		t.Fatalf("cluster scope should see its own and its resource group's assignment, got %d", len(got))
	}
	if got := AssignmentsAtOrAbove(assignments, testRGScope, ClusterAdminRoleDefinitionID); len(got) != 1 {
		t.Fatalf("resource group scope must not see a cluster-level assignment, got %d", len(got))
	}
	if got := AssignmentsAtOrAbove(assignments, testRGScope+"-other", ClusterAdminRoleDefinitionID); len(got) != 1 {
		t.Fatalf("a sibling resource group name must not match by prefix, got %d", len(got))
	}
	if got := AssignmentsAtOrAbove(assignments, testRGScope, "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"); len(got) != 1 {
		t.Fatalf("a subscription-level assignment applies to the resource group, got %d", len(got))
	}
	if got := AssignmentsAtOrAbove(assignments, testScope, "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"); len(got) != 1 {
		t.Fatalf("a subscription-level assignment applies to the cluster, got %d", len(got))
	}
}

func TestNewRoleAssignmentErrorParsesCode(t *testing.T) {
	err := newRoleAssignmentError("create", http.StatusForbidden, []byte(`{"error":{"code":"AuthorizationFailed","message":"m"}}`))
	if err.Code != "AuthorizationFailed" || err.Message != "m" {
		t.Fatalf("unexpected parse: %+v", err)
	}
	raw := newRoleAssignmentError("create", http.StatusBadGateway, []byte("gateway down"))
	if raw.Code != "" || raw.Message != "gateway down" {
		t.Fatalf("unexpected raw body parse: %+v", raw)
	}
}
