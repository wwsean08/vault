package elasticsearch

import (
	"context"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/logical/database/dbplugin"
	"github.com/hashicorp/vault/plugins"
)

// Elasticsearch implements dbplugin's Database interface
type Elasticsearch struct{}

func New() (interface{}, error) {
	return &Elasticsearch{}, nil
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

func (es *Elasticsearch) Init(ctx context.Context, config map[string]interface{}, verifyConnection bool) (saveConfig map[string]interface{}, err error) {
	// TODO
	return nil, nil
}

func (es *Elasticsearch) CreateUser(ctx context.Context, statements dbplugin.Statements, usernameConfig dbplugin.UsernameConfig, expiration time.Time) (username string, password string, err error) {
	// TODO
	return "", "", nil
}

func (es *Elasticsearch) RenewUser(ctx context.Context, statements dbplugin.Statements, username string, expiration time.Time) error {
	// TODO
	return nil
}

func (es *Elasticsearch) RevokeUser(ctx context.Context, statements dbplugin.Statements, username string) error {
	// TODO
	return nil
}

func (es *Elasticsearch) RotateRootCredentials(ctx context.Context, statements []string) (config map[string]interface{}, err error) {
	// TODO
	return nil, nil
}

func (es *Elasticsearch) Close() error {
	// TODO
	return nil
}

// DEPRECATED, will be removed in 0.13
func (es *Elasticsearch) Initialize(ctx context.Context, config map[string]interface{}, verifyConnection bool) (err error) {
	// TODO
	return nil
}
