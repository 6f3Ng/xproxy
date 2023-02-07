package goproxy

import (
	"net/http"
)

func (p *Proxy) MyServer(ctx *Context, rw http.ResponseWriter) {
	ctx.myHandleFunc("GET", "/", rw, index)
	ctx.myHandleFunc("GET", "/downloadCert", rw, downloadCert)
	ctx.myHandleFunc("GET", "/getConfig", rw, getConfig)
}

func (ctx *Context) myHandleFunc(method, path string, rw http.ResponseWriter, f func(ctx *Context, rw http.ResponseWriter)) {
	if method == ctx.Req.Method && path == ctx.Req.URL.Path {
		f(ctx, rw)
	}
}
