// Copyright 2017 Drone.IO Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package coding

import (
	"net/http"
	"strings"

	"github.com/drone/go-login/login"
	"github.com/drone/go-login/login/internal/oauth2"
	"github.com/drone/go-login/login/logger"
)

var _ login.Middleware = (*Config)(nil)

// Config configures the GitLab auth provider.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Server       string
	Scope        []string
	Client       *http.Client
	Logger       logger.Logger
	Debug        bool
}

// Handler returns a http.Handler that runs h at the
// completion of the GitLab authorization flow. The GitLab
// authorization details are available to h in the
// http.Request context.
func (c *Config) Handler(h http.Handler) http.Handler {
	server := normalizeAddress(c.Server)
	var dumper logger.Dumper
	if c.Debug {
		dumper = logger.StandardDumper()
	}

	return oauth2.Handler(h, &oauth2.Config{
		BasicAuthOff:     true,
		Client:           c.Client,
		ClientID:         c.ClientID,
		ClientSecret:     c.ClientSecret,
		RedirectURL:      c.RedirectURL,
		AccessTokenURL:   server + "/api/oauth/access_token",
		AuthorizationURL: server + "/oauth_authorize.html",
		Scope:            c.Scope,
		Logger:           c.Logger,
		Dumper:           dumper,
		ExchangeMethod:   "GET",
	})
}

func normalizeAddress(address string) string {
	if address == "" {
		return "https://coding.net"
	}
	return strings.TrimSuffix(address, "/")
}
