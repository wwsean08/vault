package elasticsearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/logical/database/dbplugin"
	"github.com/hashicorp/vault/plugins"
	"github.com/hashicorp/vault/plugins/helper/database/credsutil"
	"github.com/hashicorp/vault/plugins/helper/database/dbutil"
)

// Elasticsearch implements dbplugin's Database interface
type Elasticsearch struct {
	credentialProducer credsutil.CredentialsProducer

	// mux protects the config from races
	mux sync.Mutex

	// the root credential config
	config map[string]interface{}
}

func New() (interface{}, error) {
	return &Elasticsearch{
		credentialProducer: &credsutil.SQLCredentialsProducer{
			DisplayNameLen: 15,
			RoleNameLen:    15,
			UsernameLen:    100,
			Separator:      "-",
		},
	}, nil
}

func Run(apiTLSConfig *api.TLSConfig) error {
	dbType, err := New()
	if err != nil {
		return err
	}
	plugins.Serve(dbType.(dbplugin.Database), apiTLSConfig)
	return nil
}

func (es *Elasticsearch) Type() (string, error) {
	return "elasticsearch", nil
}

func toClientConfig(rootConfig map[string]interface{}) (*ClientConfig, error) {

	clientConfig := &ClientConfig{}

	raw, ok := rootConfig["username"]
	if !ok {
		return nil, errors.New(`"username" must be provided`)
	}
	clientConfig.Username, ok = raw.(string)
	if !ok {
		return nil, errors.New(`"username" must be a string`)
	}

	raw, ok = rootConfig["password"]
	if !ok {
		return nil, errors.New(`"password" must be provided`)
	}
	clientConfig.Password, ok = raw.(string)
	if !ok {
		return nil, errors.New(`"password" must be a string"`)
	}

	raw, ok = rootConfig["url"]
	if !ok {
		return nil, errors.New(`"url" must be provided`)
	}
	clientConfig.BaseURL, ok = raw.(string)
	if !ok {
		return nil, errors.New(`"url" must be a string`)
	}

	tlsConfigInbound := false
	inboundTLSConfig := &TLSConfig{}

	if raw, ok := rootConfig["ca_cert"]; ok {
		inboundTLSConfig.CACert, ok = raw.(string)
		if !ok {
			return nil, errors.New(`"ca_cert" must be a string`)
		}
		tlsConfigInbound = true
	}
	if raw, ok := rootConfig["ca_path"]; ok {
		inboundTLSConfig.CAPath, ok = raw.(string)
		if !ok {
			return nil, errors.New(`"ca_path" must be a string`)
		}
		tlsConfigInbound = true
	}
	if raw, ok := rootConfig["client_cert"]; ok {
		inboundTLSConfig.ClientCert, ok = raw.(string)
		if !ok {
			return nil, errors.New(`"client_cert" must be a string`)
		}
		tlsConfigInbound = true
	}
	if raw, ok := rootConfig["client_key"]; ok {
		inboundTLSConfig.ClientKey, ok = raw.(string)
		if !ok {
			return nil, errors.New(`"client_key" must be a string`)
		}
		tlsConfigInbound = true
	}
	if raw, ok := rootConfig["tls_server_name"]; ok {
		inboundTLSConfig.TLSServerName, ok = raw.(string)
		if !ok {
			return nil, errors.New(`"tls_server_name" must be a string`)
		}
		tlsConfigInbound = true
	}
	if raw, ok := rootConfig["insecure"]; ok {
		inboundTLSConfig.Insecure, ok = raw.(bool)
		if !ok {
			return nil, errors.New(`"insecure" must be a bool`)
		}
		tlsConfigInbound = true
	}

	// If no TLS config was provided, the user probably doesn't want TLS.
	// We flag this to the client by leaving the TLS config pointer nil. So, we should
	// only fulfill this pointer if the user actually wants TLS.
	if tlsConfigInbound {
		clientConfig.TLSConfig = inboundTLSConfig
	}
	return clientConfig, nil
}

// Init is called on `$ vault write database/config/:db-name`.
// or when you do a creds call after Vault's been restarted.
func (es *Elasticsearch) Init(ctx context.Context, config map[string]interface{}, verifyConnection bool) (map[string]interface{}, error) {

	inboundConfig, err := toClientConfig(config)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("couldn't convert %s to client config: {{err}}", config), err)
	}

	// Let's always do an initial check that the client config at least _looks_ reasonable.
	inboundClient, err := NewClient(inboundConfig)
	if err != nil {
		return nil, errwrap.Wrapf("couldn't make client with inbound config: {{err}}", err)
	}

	if verifyConnection {
		// Whether this role is found or unfound, if we're configured correctly there will
		// be no err from the call. However, if something is misconfigured, this will yield
		// an error response, which will be described in the returned error.
		if _, err := inboundClient.GetRole(ctx.Done(), "vault-test"); err != nil {
			return nil, errwrap.Wrapf("client test of getting a role failed: {{err}}", err)
		}
	}

	es.mux.Lock()
	defer es.mux.Unlock()
	es.config = config
	return es.config, nil
}

// CreateUser is called on `$ vault read database/creds/:role-name`
// and it's the first time anything is touched from `$ vault write database/roles/:role-name`.
func (es *Elasticsearch) CreateUser(ctx context.Context, statements dbplugin.Statements, usernameConfig dbplugin.UsernameConfig, _ time.Time) (string, string, error) {
	username, err := es.credentialProducer.GenerateUsername(usernameConfig)
	if err != nil {
		return "", "", errwrap.Wrapf(fmt.Sprintf("unable to generate username for %q: {{err}}", usernameConfig), err)
	}

	password, err := es.credentialProducer.GeneratePassword()
	if err != nil {
		return "", "", errwrap.Wrapf("unable to generate password: {{err}}", err)
	}

	stmt, err := newCreationStatement(statements)
	if err != nil {
		return "", "", errwrap.Wrapf("unable to read creation_statements: {{err}}", err)
	}

	user := &User{
		Password: password,
		Roles:    stmt.PreexistingRoles,
	}

	es.mux.Lock()
	defer es.mux.Unlock()

	clientConfig, err := toClientConfig(es.config)
	if err != nil {
		return "", "", errwrap.Wrapf("unable to get client: {{err}}", err)
	}
	client, err := NewClient(clientConfig)
	if err != nil {
		// TODO errwrap
		return "", "", err
	}
	if len(stmt.RoleToCreate) > 0 {
		if err := client.CreateRole(ctx.Done(), username, stmt.RoleToCreate); err != nil {
			return "", "", errwrap.Wrapf(fmt.Sprintf("unable to create role name %s, role definition %q: {{err}}", username, stmt.RoleToCreate), err)
		}
		user.Roles = []string{username}
	}
	if err := client.CreateUser(ctx.Done(), username, user); err != nil {
		return "", "", errwrap.Wrapf(fmt.Sprintf("unable to create user name %s, user %q: {{err}}", username, user), err)
	}
	return username, password, nil
}

// RenewUser gets called on `$ vault lease renew {{lease-id}}`. It automatically pushes out the amount of time until
// the database secrets engine calls RevokeUser, if appropriate.
func (es *Elasticsearch) RenewUser(_ context.Context, _ dbplugin.Statements, _ string, _ time.Time) error {
	// This is not implemented because you can't put an expiration on roles or users. They can only be created
	// and explicitly revoked. (Normally, this function would update a "VALID UNTIL" statement on a database user
	// but there's no similar need here.)
	return nil
}

// RevokeUser is called when a lease expires.
func (es *Elasticsearch) RevokeUser(ctx context.Context, statements dbplugin.Statements, username string) error {
	stmt, err := newCreationStatement(statements)
	if err != nil {
		return errwrap.Wrapf("unable to read creation_statements: {{err}}", err)
	}

	es.mux.Lock()
	defer es.mux.Unlock()

	clientConfig, err := toClientConfig(es.config)
	if err != nil {
		return errwrap.Wrapf("unable to get client: {{err}}", err)
	}
	client, err := NewClient(clientConfig)
	if err != nil {
		// TODO errwrap
		return err
	}

	var errs error
	if len(stmt.RoleToCreate) > 0 {
		// If the role already doesn't exist because it was successfully deleted on a previous
		// attempt to run this code, there will be no error, so it's harmless to try.
		if err := client.DeleteRole(ctx.Done(), username); err != nil {
			errs = multierror.Append(errs, errwrap.Wrapf(fmt.Sprintf("unable to delete role name %s: {{err}}", username), err))
		}
	}
	// Same with the user. If it was already deleted on a previous attempt, there won't be an
	// error.
	if err := client.DeleteUser(ctx.Done(), username); err != nil {
		errs = multierror.Append(errs, errwrap.Wrapf(fmt.Sprintf("unable to create user name %s: {{err}}", username), err))
	}
	return errs
}

func (es *Elasticsearch) RotateRootCredentials(ctx context.Context, statements []string) (map[string]interface{}, error) {
	newPassword, err := es.credentialProducer.GeneratePassword()
	if err != nil {
		return nil, errwrap.Wrapf("unable to generate root password: {{err}}", err)
	}

	es.mux.Lock()
	defer es.mux.Unlock()

	clientConfig, err := toClientConfig(es.config)
	if err != nil {
		return nil, errwrap.Wrapf("unable to get client: {{err}}", err)
	}
	client, err := NewClient(clientConfig)
	if err != nil {
		// TODO errwrap
		return nil, err
	}

	if err := client.ChangePassword(ctx.Done(), es.config["username"].(string), newPassword); err != nil {
		return nil, err
	}

	es.config["password"] = newPassword
	return es.config, nil
}

func (es *Elasticsearch) Close() error {
	// NOOP, nothing to close.
	return nil
}

// DEPRECATED, included for backward-compatibility until removal
func (es *Elasticsearch) Initialize(ctx context.Context, config map[string]interface{}, verifyConnection bool) error {
	_, err := es.Init(ctx, config, verifyConnection)
	return err
}

func newCreationStatement(statements dbplugin.Statements) (*creationStatement, error) {
	if len(statements.Creation) == 0 {
		return nil, dbutil.ErrEmptyCreationStatement
	}
	stmt := &creationStatement{}
	if err := json.Unmarshal([]byte(statements.Creation[0]), stmt); err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("unable to unmarshal %s: {{err}}", []byte(statements.Creation[0])), err)
	}
	if len(stmt.PreexistingRoles) > 0 && len(stmt.RoleToCreate) > 0 {
		return nil, errors.New(`"elasticsearch_roles" and "elasticsearch_role_definition" are mutually exclusive`)
	}
	return stmt, nil
}

type creationStatement struct {
	PreexistingRoles []string               `json:"elasticsearch_roles"`
	RoleToCreate     map[string]interface{} `json:"elasticsearch_role_definition"`
}
