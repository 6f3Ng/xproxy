// Package goproxy HTTP(S)代理, 支持中间人代理解密HTTPS数据
package goproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"xproxy/cert"
	"xproxy/global"
)

const (
	// 连接目标服务器超时时间
	defaultTargetConnectTimeout = 5 * time.Second
	// 目标服务器读写超时时间
	defaultTargetReadWriteTimeout = 30 * time.Second
	// 客户端读写超时时间
	defaultClientReadWriteTimeout = 30 * time.Second
)

var (
	// 隧道连接成功响应
	tunnelEstablishedResponseLine = []byte("HTTP/1.1 200 Connection established\r\n\r\n")
	// 代理认证失败响应
	proxyAuthorizationRequired = []byte("HTTP/1.1 407 \r\nConnection: close\r\nProxy Authorization Required\r\nProxy-Authenticate: Basic realm=\"Access to internal site\"\r\n\r\n")
	// proxyAuthorizationRequiredFromXray = []byte("HTTP/1.1 407 200 OK \r\nConnection: close\r\nProxy-Authenticate: Basic\r\nWarning: 199 \"martian\" \"auth error\" \"" + time.Now().Local().String() + "\"\r\nContent-Length: 0\r\n\r\n")

	badGateway = []byte(fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", http.StatusBadGateway, http.StatusText(http.StatusBadGateway)))

	// 下载证书
	// downloadCertResponseLine = []byte(fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-type: text/plain\r\nContent-length: %d\r\n\r\n%s", http.StatusOK, http.StatusText(http.StatusOK), len(cert.GetDefaultRootCAPem()), string(cert.GetDefaultRootCAPem())))
)

// 生成隧道建立请求行
func makeTunnelRequestLine(addr string) string {
	return fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", addr)
}

type options struct {
	disableKeepAlive bool
	delegate         Delegate
	decryptHTTPS     bool
	certCache        cert.Cache
	transport        *http.Transport
}

type Option func(*options)

// WithDisableKeepAlive 连接是否重用
func WithDisableKeepAlive(disableKeepAlive bool) Option {
	return func(opt *options) {
		opt.disableKeepAlive = disableKeepAlive
	}
}

// WithDelegate 设置委托类
func WithDelegate(delegate Delegate) Option {
	return func(opt *options) {
		opt.delegate = delegate
	}
}

// WithTransport 自定义http transport
func WithTransport(t *http.Transport) Option {
	return func(opt *options) {
		opt.transport = t
	}
}

// WithDecryptHTTPS 中间人代理, 解密HTTPS, 需实现证书缓存接口
func WithDecryptHTTPS(c cert.Cache) Option {
	return func(opt *options) {
		opt.decryptHTTPS = true
		opt.certCache = c
	}
}

// New 创建proxy实例
func New(opt ...Option) *Proxy {
	opts := &options{}
	for _, o := range opt {
		o(opts)
	}
	if opts.delegate == nil {
		opts.delegate = &DefaultDelegate{}
	}
	if opts.transport == nil {
		opts.transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	p := &Proxy{}
	p.delegate = opts.delegate
	p.decryptHTTPS = opts.decryptHTTPS
	if p.decryptHTTPS {
		p.cert = cert.NewCertificate(opts.certCache)
	}
	p.transport = opts.transport
	p.transport.DisableKeepAlives = opts.disableKeepAlive
	p.transport.Proxy = p.delegate.ParentProxy

	return p
}

// Proxy 实现了http.Handler接口
type Proxy struct {
	delegate      Delegate
	clientConnNum int32
	decryptHTTPS  bool
	cert          *cert.Certificate
	transport     *http.Transport
}

func (p *Proxy) checkListenAddr(host string) bool {
	listenIp, listenPort, _ := net.SplitHostPort(global.ListenAddr)
	reqIp, reqPort, _ := net.SplitHostPort(host)
	if listenPort != reqPort {
		return false
	}
	if listenIp != "" {
		if reqIp == listenIp {
			return true
		} else {
			return false
		}
	} else {
		for _, v := range global.IpLists {
			if v == reqIp {
				return true
			}
		}
		return false
	}
}

var _ http.Handler = &Proxy{}

// ServeHTTP 实现了http.Handler接口
func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	var reqHost string

	if strings.Contains(req.URL.Host, ":") {
		reqHost = req.URL.Host
	} else {
		if req.URL.Scheme == "http" {
			reqHost = req.URL.Host + ":80"
		} else {
			reqHost = req.URL.Host + ":443"
		}
	}

	// log.Println(reqHost)

	atomic.AddInt32(&p.clientConnNum, 1)
	defer func() {
		atomic.AddInt32(&p.clientConnNum, -1)
	}()
	ctx := &Context{
		Req:  req,
		Data: make(map[interface{}]interface{}),
	}
	defer p.delegate.Finish(ctx)

	p.delegate.Connect(ctx, rw)
	if ctx.abort {
		return
	}
	p.delegate.Auth(ctx, rw)
	if ctx.abort {
		p.NeedAuth(rw)
		// p.forwardAbort(ctx, rw)
		return
	}

	// 解决无限连接循环问题，访问监听端口为程序web页面
	if p.checkListenAddr(reqHost) {
		p.MyServer(ctx, rw)
		return
	}

	switch {
	case ctx.Req.Method == http.MethodConnect && p.decryptHTTPS:
		p.forwardHTTPS(ctx, rw)
	case ctx.Req.Method == http.MethodConnect:
		p.forwardTunnel(ctx, rw)
	default:
		p.forwardHTTP(ctx, rw)
	}
}

// ClientConnNum 获取客户端连接数
func (p *Proxy) ClientConnNum() int32 {
	return atomic.LoadInt32(&p.clientConnNum)
}

func (p *Proxy) NeedAuth(rw http.ResponseWriter) {
	// hj, _ := rw.(http.Hijacker)
	// Client, _, err := hj.Hijack()
	Client, err := hijacker(rw)
	if err != nil {
		p.delegate.ErrorLog(fmt.Errorf("fail to get TCP connection of client in auth, %v", err))
		return
	}
	defer Client.Close()
	_, _ = Client.Write(proxyAuthorizationRequired)
}

// 下载证书
// func (p *Proxy) DownloadCert(rw http.ResponseWriter) {
// 	resp := &http.Response{
// 		StatusCode: http.StatusOK,
// 		Status:     http.StatusText(http.StatusOK),
// 		Body:       ioutil.NopCloser(bytes.NewBuffer(cert.GetDefaultRootCAPem())),
// 	}

// 	removeConnectionHeaders(resp.Header)
// 	for _, h := range hopHeaders {
// 		resp.Header.Del(h)
// 	}

// 	defer resp.Body.Close()
// 	CopyHeader(rw.Header(), resp.Header)
// 	rw.WriteHeader(resp.StatusCode)
// 	io.Copy(rw, resp.Body)
// }

// func (p *Proxy) DownloadCertRequest(ctx *Context, responseFunc func(*http.Response, error)) {

// 	responseFunc(resp, nil)
// }

// DoRequest 执行HTTP请求，并调用responseFunc处理response
func (p *Proxy) DoRequest(ctx *Context, responseFunc func(*http.Response, error)) {
	if ctx.Data == nil {
		ctx.Data = make(map[interface{}]interface{})
	}
	p.delegate.BeforeRequest(ctx)
	if ctx.abort {
		p.delegate.ErrorLog(fmt.Errorf("BeforeRequest err from %s", ctx.Req.URL.Host))
		abortResp := &http.Response{
			StatusCode: http.StatusGatewayTimeout,
			Status:     http.StatusText(http.StatusGatewayTimeout),
			Body:       ioutil.NopCloser(bytes.NewBufferString("")),
		}
		responseFunc(abortResp, nil)
		return
	}
	newReq := new(http.Request)
	*newReq = *ctx.Req
	newReq.Header = CloneHeader(newReq.Header)
	removeConnectionHeaders(newReq.Header)
	for _, item := range hopHeaders {
		if newReq.Header.Get(item) != "" {
			newReq.Header.Del(item)
		}
	}
	resp, err := p.transport.RoundTrip(newReq)
	p.delegate.BeforeResponse(ctx, resp, err)
	if ctx.abort {
		p.delegate.ErrorLog(fmt.Errorf("BeforeResponse err from %s", ctx.Req.URL.Host))
		abortResp := &http.Response{
			StatusCode: http.StatusGatewayTimeout,
			Status:     http.StatusText(http.StatusGatewayTimeout),
			Body:       ioutil.NopCloser(bytes.NewBufferString("")),
		}
		responseFunc(abortResp, nil)
		return
	}
	if err == nil {
		removeConnectionHeaders(resp.Header)
		for _, h := range hopHeaders {
			resp.Header.Del(h)
		}
	}
	responseFunc(resp, err)
}

// HTTP转发
func (p *Proxy) forwardHTTP(ctx *Context, rw http.ResponseWriter) {
	ctx.Req.URL.Scheme = "http"
	p.DoRequest(ctx, func(resp *http.Response, err error) {
		if err != nil {
			p.delegate.ErrorLog(fmt.Errorf("%s - HTTP请求错误: , 错误: %s", ctx.Req.URL, err))
			rw.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		CopyHeader(rw.Header(), resp.Header)
		rw.WriteHeader(resp.StatusCode)
		io.Copy(rw, resp.Body)
	})
}

// HTTPS转发
func (p *Proxy) forwardHTTPS(ctx *Context, rw http.ResponseWriter) {
	clientConn, err := hijacker(rw)
	if err != nil {
		p.delegate.ErrorLog(err)
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	defer clientConn.Close()
	_, err = clientConn.Write(tunnelEstablishedResponseLine)
	if err != nil {
		p.delegate.ErrorLog(fmt.Errorf("%s - HTTPS解密, 通知客户端隧道已连接失败, %s", ctx.Req.URL.Host, err))
		return
	}
	tlsConfig, err := p.cert.GenerateTlsConfig(ctx.Req.URL.Host)
	if err != nil {
		p.delegate.ErrorLog(fmt.Errorf("%s - HTTPS解密, 生成证书失败: %s", ctx.Req.URL.Host, err))
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	tlsClientConn.SetDeadline(time.Now().Add(defaultClientReadWriteTimeout))
	defer tlsClientConn.Close()
	if err := tlsClientConn.Handshake(); err != nil {
		p.delegate.ErrorLog(fmt.Errorf("%s - HTTPS解密, 握手失败: %s", ctx.Req.URL.Host, err))
		return
	}
	buf := bufio.NewReader(tlsClientConn)
	tlsReq, err := http.ReadRequest(buf)
	if err != nil {
		if err != io.EOF {
			p.delegate.ErrorLog(fmt.Errorf("%s - HTTPS解密, 读取客户端请求失败: %s", ctx.Req.URL.Host, err))
		}
		return
	}
	tlsReq.RemoteAddr = ctx.Req.RemoteAddr
	tlsReq.URL.Scheme = "https"
	tlsReq.URL.Host = tlsReq.Host

	ctx.Req = tlsReq
	p.DoRequest(ctx, func(resp *http.Response, err error) {
		if err != nil {
			p.delegate.ErrorLog(fmt.Errorf("%s - HTTPS解密, 请求错误: %s", ctx.Req.URL, err))
			tlsClientConn.Write(badGateway)
			return
		}
		err = resp.Write(tlsClientConn)
		if err != nil {
			p.delegate.ErrorLog(fmt.Errorf("%s - HTTPS解密, response写入客户端失败, %s", ctx.Req.URL, err))
		}
		resp.Body.Close()
	})
}

// 隧道转发
func (p *Proxy) forwardTunnel(ctx *Context, rw http.ResponseWriter) {
	clientConn, err := hijacker(rw)
	if err != nil {
		p.delegate.ErrorLog(err)
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	defer clientConn.Close()
	parentProxyURL, err := p.delegate.ParentProxy(ctx.Req)
	if err != nil {
		p.delegate.ErrorLog(fmt.Errorf("%s - 解析代理地址错误: %s", ctx.Req.URL.Host, err))
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	targetAddr := ctx.Req.URL.Host
	if parentProxyURL != nil {
		targetAddr = parentProxyURL.Host
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, defaultTargetConnectTimeout)
	if err != nil {
		p.delegate.ErrorLog(fmt.Errorf("%s - 隧道转发连接目标服务器失败: %s", ctx.Req.URL.Host, err))
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	clientConn.SetDeadline(time.Now().Add(defaultClientReadWriteTimeout))
	targetConn.SetDeadline(time.Now().Add(defaultTargetReadWriteTimeout))
	if parentProxyURL == nil {
		_, err = clientConn.Write(tunnelEstablishedResponseLine)
		if err != nil {
			p.delegate.ErrorLog(fmt.Errorf("%s - 隧道连接成功,通知客户端错误: %s", ctx.Req.URL.Host, err))
			return
		}
	} else {
		tunnelRequestLine := makeTunnelRequestLine(ctx.Req.URL.Host)
		targetConn.Write([]byte(tunnelRequestLine))
	}

	p.transfer(clientConn, targetConn)
}

// 双向转发
func (p *Proxy) transfer(src net.Conn, dst net.Conn) {
	go func() {
		io.Copy(src, dst)
		src.Close()
		dst.Close()
	}()

	io.Copy(dst, src)
	dst.Close()
	src.Close()
}

// 获取底层连接
func hijacker(rw http.ResponseWriter) (net.Conn, error) {
	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("web server不支持Hijacker")
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijacker错误: %s", err)
	}

	return conn, nil
}

// CopyHeader 浅拷贝Header
func CopyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// CloneHeader 深拷贝Header
func CloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

// CloneBody 拷贝Body
func CloneBody(b io.ReadCloser) (r io.ReadCloser, body []byte, err error) {
	if b == nil {
		return http.NoBody, nil, nil
	}
	body, err = ioutil.ReadAll(b)
	if err != nil {
		return http.NoBody, nil, err
	}
	r = ioutil.NopCloser(bytes.NewReader(body))

	return r, body, nil
}

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeConnectionHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
}
