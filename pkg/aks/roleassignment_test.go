package aks

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	first := RoleAssignmentName(testScope, testOID)
	second := RoleAssignmentName(testScope, testOID)
	if first != second {
		t.Fatalf("name changed between calls: %q and %q", first, second)
	}
	if !guidFormat.MatchString(first) {
		t.Fatalf("name %q is not a version 5 GUID", first)
	}
	if other := RoleAssignmentName(testScope, "99999999-2222-3333-4444-555555555555"); other == first {
		t.Fatalf("different principals produced the same name %q", first)
	}
}

func TestEnsureClusterAdminRoleAssignmentCreates(t *testing.T) {
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
	name, owned, err := EnsureClusterAdminRoleAssignment(context.Background(), cred, armConfig(srv.URL), testScope, testOID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !owned {
		t.Fatal("expected the operator to own the created assignment")
	}
	if name != RoleAssignmentName(testScope, testOID) {
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
}

func TestEnsureClusterAdminRoleAssignmentExistingEquivalent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"RoleAssignmentExists","message":"exists"}}`))
	}))
	defer srv.Close()

	_, owned, err := EnsureClusterAdminRoleAssignment(context.Background(), fakeTokenCredential{token: testToken}, armConfig(srv.URL), testScope, testOID)
	if err != nil {
		t.Fatalf("an existing equivalent assignment should not be an error: %v", err)
	}
	if owned {
		t.Fatal("an assignment created outside the operator must not be marked as owned")
	}
}

func TestEnsureClusterAdminRoleAssignmentFailures(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "transient throttling", status: http.StatusTooManyRequests, body: `{"error":{"code":"TooManyRequests"}}`},
		{name: "server error", status: http.StatusInternalServerError, body: `{"error":{"code":"InternalError"}}`},
		{name: "authorization failure", status: http.StatusForbidden, body: `{"error":{"code":"AuthorizationFailed"}}`},
		{name: "principal not yet replicated", status: http.StatusBadRequest, body: `{"error":{"code":"PrincipalNotFound"}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, owned, err := EnsureClusterAdminRoleAssignment(context.Background(), fakeTokenCredential{token: testToken}, armConfig(srv.URL), testScope, testOID)
			if err == nil {
				t.Fatal("expected an error so the caller can retry or report it")
			}
			if owned {
				t.Fatal("a failed request must not be marked as owned")
			}
		})
	}
}

func TestEnsureClusterAdminRoleAssignmentTokenFailure(t *testing.T) {
	cred := fakeTokenCredential{err: context.DeadlineExceeded}
	_, _, err := EnsureClusterAdminRoleAssignment(context.Background(), cred, armConfig("http://unused"), testScope, testOID)
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

func TestDeleteClusterAdminRoleAssignment(t *testing.T) {
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

			err := DeleteClusterAdminRoleAssignment(context.Background(), fakeTokenCredential{token: testToken}, armConfig(srv.URL), testScope, "name")
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
