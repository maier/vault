package approle

import (
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/mitchellh/mapstructure"
)

func TestBackend_role_delete_secret_id(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createRole(t, b, storage, "role1", "a,b")
	secretIDReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "role/role1/secret-id",
	}
	// Create 3 secrets on the role
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Storage:   storage,
		Path:      "role/role1/secret-id",
	}
	resp, err = b.HandleRequest(listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	secretIDAccessors := resp.Data["keys"].([]string)
	if len(secretIDAccessors) != 3 {
		t.Fatalf("bad: len of secretIDAccessors: expected:3 actual:%d", len(secretIDAccessors))
	}

	roleReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Storage:   storage,
		Path:      "role/role1",
	}
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	resp, err = b.HandleRequest(listReq)
	if err != nil || resp == nil || (resp != nil && !resp.IsError()) {
		t.Fatalf("expected an error. err:%v resp:%#v", err, resp)
	}
}

func TestBackend_role_secret_id_read_delete(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createRole(t, b, storage, "role1", "a,b")
	secretIDReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "role/role1/secret-id",
	}
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Storage:   storage,
		Path:      "role/role1/secret-id",
	}
	resp, err = b.HandleRequest(listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	hmacSecretID := resp.Data["keys"].([]string)[0]

	hmacReq := &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   storage,
		Path:      "role/role1/secret-id/" + hmacSecretID,
	}
	resp, err = b.HandleRequest(hmacReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	result := secretIDStorageEntry{}
	if err := mapstructure.Decode(resp.Data, &result); err != nil {
		t.Fatal(err)
	}

	hmacReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(hmacReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	hmacReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(hmacReq)
	if resp != nil && resp.IsError() {
		t.Fatalf("error response:%#v", err, resp)
	}
	if err == nil {
		t.Fatalf("expected an error")
	}
}

func TestBackend_role_list_secret_id(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createRole(t, b, storage, "role1", "a,b")

	secretIDReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Path:      "role/role1/secret-id",
	}
	// Create 5 'secret_id's
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Storage:   storage,
		Path:      "role/role1/secret-id/",
	}
	resp, err = b.HandleRequest(listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	secrets := resp.Data["keys"].([]string)
	if len(secrets) != 5 {
		t.Fatalf("bad: len of secrets: expected:5 actual:%d", len(secrets))
	}
}

func TestBackend_role_list(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createRole(t, b, storage, "role1", "a,b")
	createRole(t, b, storage, "role2", "c,d")
	createRole(t, b, storage, "role3", "e,f")
	createRole(t, b, storage, "role4", "g,h")
	createRole(t, b, storage, "role5", "i,j")

	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	actual := resp.Data["keys"].([]string)
	expected := []string{"role1", "role2", "role3", "role4", "role5"}
	if !policyutil.EquivalentPolicies(actual, expected) {
		t.Fatalf("bad: listed roles: expected:%s\nactual:%s", expected, actual)
	}
}

func TestBackend_role_secret_id(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	roleData := map[string]interface{}{
		"policies":           "p,q,r,s",
		"secret_id_num_uses": 10,
		"secret_id_ttl":      300,
		"token_ttl":          400,
		"token_max_ttl":      500,
	}
	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/role1",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleSecretIDReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/role1/secret-id",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(roleSecretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id"].(string) == "" {
		t.Fatalf("failed to generate secret_id")
	}

	roleSecretIDReq.Path = "role/role1/custom-secret-id"
	roleCustomSecretIDData := map[string]interface{}{
		"secret_id": "abcd123",
	}
	roleSecretIDReq.Data = roleCustomSecretIDData
	roleSecretIDReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(roleSecretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id"] != "abcd123" {
		t.Fatalf("failed to set specific secret_id to role")
	}
}

func TestBackend_role_CRUD(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	roleData := map[string]interface{}{
		"policies":           "p,q,r,s",
		"secret_id_num_uses": 10,
		"secret_id_ttl":      300,
		"token_ttl":          400,
		"token_max_ttl":      500,
		"bound_cidr_list":    "127.0.0.1/32,127.0.0.1/16",
	}
	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/role1",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	expected := map[string]interface{}{
		"bound_secret_id":    true,
		"policies":           []string{"default", "p", "q", "r", "s"},
		"secret_id_num_uses": 10,
		"secret_id_ttl":      300,
		"token_ttl":          400,
		"token_max_ttl":      500,
		"bound_cidr_list":    "127.0.0.1/32,127.0.0.1/16",
	}
	var expectedStruct roleStorageEntry
	err = mapstructure.Decode(expected, &expectedStruct)
	if err != nil {
		t.Fatal(err)
	}

	var actualStruct roleStorageEntry
	err = mapstructure.Decode(resp.Data, &actualStruct)
	if err != nil {
		t.Fatal(err)
	}

	expectedStruct.RoleID = actualStruct.RoleID
	if !reflect.DeepEqual(expectedStruct, actualStruct) {
		t.Fatalf("bad:\nexpected:%#v\nactual:%#v\n", expectedStruct, actualStruct)
	}

	roleData = map[string]interface{}{
		"role_id":            "test_role_id",
		"policies":           "a,b,c,d",
		"secret_id_num_uses": 100,
		"secret_id_ttl":      3000,
		"token_ttl":          4000,
		"token_max_ttl":      5000,
	}
	roleReq.Data = roleData
	roleReq.Operation = logical.UpdateOperation

	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	expected = map[string]interface{}{
		"policies":           []string{"a", "b", "c", "d", "default"},
		"secret_id_num_uses": 100,
		"secret_id_ttl":      3000,
		"token_ttl":          4000,
		"token_max_ttl":      5000,
	}
	err = mapstructure.Decode(expected, &expectedStruct)
	if err != nil {
		t.Fatal(err)
	}

	err = mapstructure.Decode(resp.Data, &actualStruct)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expectedStruct, actualStruct) {
		t.Fatalf("bad:\nexpected:%#v\nactual:%#v\n", expectedStruct, actualStruct)
	}

	// RU for role_id field
	roleReq.Path = "role/role1/role-id"
	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	if resp.Data["role_id"].(string) != "test_role_id" {
		t.Fatalf("bad: role_id: expected:test_role_id actual:%s\n", resp.Data["role_id"].(string))
	}

	roleReq.Data = map[string]interface{}{"role_id": "custom_role_id"}
	roleReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	if resp.Data["role_id"].(string) != "custom_role_id" {
		t.Fatalf("bad: role_id: expected:custom_role_id actual:%s\n", resp.Data["role_id"].(string))
	}

	// RUD for bound_secret_id field
	roleReq.Path = "role/role1/bound-secret-id"
	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Data = map[string]interface{}{"bound_secret_id": false}
	roleReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["bound_secret_id"].(bool) {
		t.Fatalf("bad: bound_secret_id: expected:false actual:%t\n", resp.Data["bound_secret_id"].(bool))
	}
	roleReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if !resp.Data["bound_secret_id"].(bool) {
		t.Fatalf("expected the default value of 'true' to be set")
	}

	// RUD for policiess field
	roleReq.Path = "role/role1/policies"
	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Data = map[string]interface{}{"policies": "a1,b1,c1,d1"}
	roleReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if !reflect.DeepEqual(resp.Data["policies"].([]string), []string{"a1", "b1", "c1", "d1", "default"}) {
		t.Fatalf("bad: policies: actual:%s\n", resp.Data["policies"].([]string))
	}
	roleReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	expectedPolicies := []string{"default"}
	actualPolicies := resp.Data["policies"].([]string)
	if !policyutil.EquivalentPolicies(expectedPolicies, actualPolicies) {
		t.Fatalf("bad: policies: expected:%s actual:%s", expectedPolicies, actualPolicies)
	}

	// RUD for num-uses field
	roleReq.Path = "role/role1/num-uses"
	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Data = map[string]interface{}{"secret_id_num_uses": 200}
	roleReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id_num_uses"].(int) != 200 {
		t.Fatalf("bad: secret_id_num_uses: expected:200 actual:%d\n", resp.Data["secret_id_num_uses"].(int))
	}
	roleReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id_num_uses"].(int) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for secret_id_ttl field
	roleReq.Path = "role/role1/secret-id-ttl"
	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Data = map[string]interface{}{"secret_id_ttl": 3001}
	roleReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id_ttl"].(time.Duration) != 3001 {
		t.Fatalf("bad: secret_id_ttl: expected:3001 actual:%d\n", resp.Data["secret_id_ttl"].(time.Duration))
	}
	roleReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id_ttl"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for 'period' field
	roleReq.Path = "role/role1/period"
	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Data = map[string]interface{}{"period": 9001}
	roleReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["period"].(time.Duration) != 9001 {
		t.Fatalf("bad: period: expected:9001 actual:%d\n", resp.Data["9001"].(time.Duration))
	}
	roleReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["period"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for token_ttl field
	roleReq.Path = "role/role1/token-ttl"
	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Data = map[string]interface{}{"token_ttl": 4001}
	roleReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["token_ttl"].(time.Duration) != 4001 {
		t.Fatalf("bad: token_ttl: expected:4001 actual:%d\n", resp.Data["token_ttl"].(time.Duration))
	}
	roleReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["token_ttl"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for token_max_ttl field
	roleReq.Path = "role/role1/token-max-ttl"
	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Data = map[string]interface{}{"token_max_ttl": 5001}
	roleReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["token_max_ttl"].(time.Duration) != 5001 {
		t.Fatalf("bad: token_max_ttl: expected:5001 actual:%d\n", resp.Data["token_max_ttl"].(time.Duration))
	}
	roleReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["token_max_ttl"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// Delete test for role
	roleReq.Path = "role/role1"
	roleReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	roleReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp != nil {
		t.Fatalf("expected a nil response")
	}
}

func createRole(t *testing.T, b *backend, s logical.Storage, roleName, policies string) {
	roleData := map[string]interface{}{
		"policies":           policies,
		"secret_id_num_uses": 10,
		"secret_id_ttl":      300,
		"token_ttl":          400,
		"token_max_ttl":      500,
	}
	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/" + roleName,
		Storage:   s,
		Data:      roleData,
	}

	resp, err := b.HandleRequest(roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
}
