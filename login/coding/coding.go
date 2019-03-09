// Copyright 2017 Drone.IO Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package coding

import (
	"net/http"
	"strings"

	"github.com/drone/go-login/login"
	"github.com/drone/go-login/login/logger"
)

var _ login.Middleware = (*Config)(nil)

// Config configures the GitLab auth provider.
type Config struct {
	Ticket string
	Server string
	Client *http.Client
	Logger logger.Logger
	Debug  bool
}

// Handler returns a http.Handler that runs h at the
// completion of the GitLab authorization flow. The GitLab
// authorization details are available to h in the
// http.Request context.
func (c *Config) Handler(h http.Handler) http.Handler {
	v := &handler{
		next:   h,
		ticket: c.Ticket,
		server: strings.TrimSuffix(c.Server, "/"),
		client: c.Client,
	}
	if v.client == nil {
		v.client = http.DefaultClient
	}

	return v
}
