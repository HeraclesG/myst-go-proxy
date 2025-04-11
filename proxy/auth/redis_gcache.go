package auth

import (
	"time"

	"github.com/HeraclesG/myst-go-proxy/proxy"
	"github.com/bluele/gcache"
)

type RedisGCache struct {
	parser   proxy.UsernameParser
	cache    gcache.Cache
	cacheTTL time.Duration
}

func NewRedisGCache(
	records int,
	cacheTTL time.Duration,
	redisCh string,
	parser proxy.UsernameParser,
) (*RedisGCache, error) {
	cache := gcache.New(records).
		LRU().
		Build()

	r := &RedisGCache{
		parser:   parser,
		cache:    cache,
		cacheTTL: cacheTTL,
	}

	return r, nil
}

func (r *RedisGCache) Authenticate(username string, password string) error {
	if username != "nenad" {
		return proxy.ErrInvalidCredentials
	} else if password != "123456" {
		return proxy.ErrInvalidCredentials
	}

	return nil
}
