package coding

import (
	"fmt"
	"github.com/drone/go-login/login"
	"net/http"
)

type handler struct {
	next   http.Handler
	ticket string
	server string
	client *http.Client
}

// 设置全局上下文token
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.ticket == "" {
		ctx = login.WithError(ctx, fmt.Errorf("请设置coding ticket"))
	} else {
		ctx = login.WithToken(ctx, &login.Token{Access: h.ticket})
	}

	h.next.ServeHTTP(w, r.WithContext(ctx))
}
