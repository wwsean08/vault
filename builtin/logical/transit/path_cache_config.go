package transit

import (
	"context"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) pathCacheConfig() *framework.Path {
	return &framework.Path{
		Pattern: "cache-config",
		Fields: map[string]*framework.FieldSchema{
			"size": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Required:    false,
				Default:     0,
				Description: `Size of cache, use 0 for an unlimited cache size, defaults to 0`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCacheConfigRead,
				Summary:  "Returns the size of the active cache",
			},

			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCacheConfigWrite,
				Summary:  "Configures a new cache of the specified size",
			},

			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathCacheConfigWrite,
				Summary:  "Configures a new cache of the specified size",
			},
		},

		HelpSynopsis:    pathCacheConfigHelpSyn,
		HelpDescription: pathCacheConfigHelpDesc,
	}
}

func (b *backend) pathCacheConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// get target size
	cacheSize := d.Get("size").(int)
	err := b.lm.SetCacheSize(cacheSize)
	if err != nil {
		return nil, errwrap.Wrapf("failed to set cache size: {{err}}", err)
	}

	// store cache size
	entry, err := logical.StorageEntryJSON("config/cache-size", &configCacheSize{
		Size: cacheSize,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

type configCacheSize struct {
	Size int `json:"size"`
}

func (b *backend) pathCacheConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{
		Data: map[string]interface{}{
			"cache_size": b.lm.GetCacheSize(),
		},
	}

	return resp, nil
}

const pathCacheConfigHelpSyn = `Configure caching strategy`

const pathCacheConfigHelpDesc = `
This path is used to configure and query the cache size of the active cache, a size of 0 means unlimited.
`
