package traefik_ultimate_bad_bot_blocker

import (
	"context"
	"net/http"
)

type Config struct {
}

func CreateConfig() *Config {
	return &Config{}
}

type BotBlocker struct {
	next http.Handler
	name string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &BotBlocker{
		name: name,
		next: next,
	}, nil
}

func (b *BotBlocker) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	b.next.ServeHTTP(rw, req)
}
