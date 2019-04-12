package transit

import (
	"context"
	"strconv"
	"strings"

<<<<<<< HEAD
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/framework"
=======
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/keysutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
>>>>>>> applies changes to cache-config when the backend is restarted and removes a bunch of unneeded code
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	// update conf with stored cache size if there is one
	if !conf.System.CachingDisabled() {
		cacheSize, err := getCacheSizeFromStorage(ctx, conf.StorageView)
		if err != nil {
			return nil, errwrap.Wrapf("Error reading configured cache size from storage: {{err}}", err)
		}
		conf.Config["cacheSize"] = strconv.Itoa(cacheSize)
	}

	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func Backend(conf *logical.BackendConfig) (*backend, error) {
	var b backend
	b.Backend = &framework.Backend{
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"archive/",
				"policy/",
			},
		},

		Paths: []*framework.Path{
			// Rotate/Config needs to come before Keys
			// as the handler is greedy
			b.pathConfig(),
			b.pathRotate(),
			b.pathRewrap(),
			b.pathKeys(),
			b.pathListKeys(),
			b.pathExportKeys(),
			b.pathEncrypt(),
			b.pathDecrypt(),
			b.pathDatakey(),
			b.pathRandom(),
			b.pathHash(),
			b.pathHMAC(),
			b.pathSign(),
			b.pathVerify(),
			b.pathBackup(),
			b.pathRestore(),
			b.pathTrim(),
			b.pathCacheConfig(),
		},

		Secrets:     []*framework.Secret{},
		Invalidate:  b.invalidate,
		BackendType: logical.TypeLogical,
	}

	cacheSize := 0
	cacheSizeStr, OK := conf.Config["cacheSize"]
	if OK {
		var err error
		cacheSize, err = strconv.Atoi(cacheSizeStr)
		if err != nil {
			return nil, err
		}
	}

	var err error
	b.lm, err = keysutil.NewLockManager(conf.System.CachingDisabled(), cacheSize)
	if err != nil {
		return nil, err
	}

	return &b, nil
}

type backend struct {
	*framework.Backend
	lm *keysutil.LockManager
}

// fetch the cache size configured in storage
func getCacheSizeFromStorage(ctx context.Context, s logical.Storage) (int, error) {
	size := 0
	entry, err := s.Get(ctx, "config/cache-size")
	if err != nil {
		return 0, err
	}
	if entry != nil {
		var storedCacheSize configCacheSize
		if err := entry.DecodeJSON(&storedCacheSize); err != nil {
			return 0, err
		}
		size = storedCacheSize.Size
	}
	return size, nil
}

func (b *backend) invalidate(_ context.Context, key string) {
	if b.Logger().IsDebug() {
		b.Logger().Debug("invalidating key", "key", key)
	}
	switch {
	case strings.HasPrefix(key, "policy/"):
		name := strings.TrimPrefix(key, "policy/")
		b.lm.InvalidatePolicy(name)
	}
}
