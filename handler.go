package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"xproxy/config"
	"xproxy/goproxy"
	"xproxy/utils"
)

type EventHandler struct{}

func (e *EventHandler) Connect(ctx *goproxy.Context, rw http.ResponseWriter) {
	// fmt.Printf("connect to: %s \n", ctx.Req.URL)
	// 保存的数据可以在后面的回调方法中获取
	// ctx.Data["req_id"] = "uuid"

	// 是否在allow_ip_range中，否则禁止访问
	if !config.CheckAllowIpRange(ctx.Req.RemoteAddr, yamlConfig.MitmConfig.AllowIpRange) {
		ctx.Abort()
		return
	}

	// 初始化一些标志位
	yamlConfig.MitmConfig.HttpDump.RequestHeader = ""
	yamlConfig.MitmConfig.HttpDump.RequestBody = ""
	yamlConfig.MitmConfig.HttpDump.ResponseHeader = ""
	yamlConfig.MitmConfig.HttpDump.ResponseBody = ""

	// 禁止访问某个域名
	// if strings.Contains(ctx.Req.URL.Host, "example.com") {
	//     rw.WriteHeader(http.StatusForbidden)
	//     ctx.Abort()
	//     return
	// }
}

func (e *EventHandler) Auth(ctx *goproxy.Context, rw http.ResponseWriter) {
	// fmt.Printf("auth to: %s \n", ctx.Req.URL)

	if yamlConfig.MitmConfig.BasicAuth.Username != "" {
		authString := ctx.Req.Header.Get("Proxy-Authorization")
		if authString == "" {
			ctx.Abort()
			return
		}
		user, pass, ok := parseBasicAuth(authString)
		if !ok || user != yamlConfig.MitmConfig.BasicAuth.Username || pass != yamlConfig.MitmConfig.BasicAuth.Password {
			// fmt.Println(user, pass)
			ctx.Abort()
			return
		}
	}
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

func (e *EventHandler) BeforeRequest(ctx *goproxy.Context) {
	// fmt.Printf("BeforeRequest to: %s \n", ctx.Req.URL)

	yamlConfig.MitmConfig.Restriction.FlagRestriction = config.CheckRestriction(ctx, yamlConfig.MitmConfig.Restriction)
	// 修改header

	if yamlConfig.MitmConfig.Restriction.FlagRestriction {
		for k, v := range yamlConfig.MitmConfig.CustomHeader.Reset {
			ctx.Req.Header.Set(k, v)
		}
		for k, v := range yamlConfig.MitmConfig.CustomHeader.Add {
			if prior, ok := ctx.Req.Header[k]; ok {
				prior = append(prior, v)
				newPrior := strings.Join(prior, "")
				ctx.Req.Header.Set(k, newPrior)
			} else {
				ctx.Req.Header.Set(k, v)
			}
		}
		for _, v := range yamlConfig.MitmConfig.CustomHeader.Delete {
			ctx.Req.Header.Del(v)
		}
		for i, v := range yamlConfig.MitmConfig.CustomReplaces {
			yamlConfig.MitmConfig.CustomReplaces[i].FlagReq = config.CheckReqConditions(ctx, v.Conditions)
			// log.Println(v.FlagReq)
			if yamlConfig.MitmConfig.CustomReplaces[i].FlagReq {
				ctx.Req, _ = config.DoReqReplace(ctx, v.Replaces)
			}
		}
		if yamlConfig.MitmConfig.HttpDump.DumpPath != "" {
			yamlConfig.MitmConfig.HttpDump.FlagReq = config.CheckReqConditions(ctx, yamlConfig.MitmConfig.HttpDump.Conditions)
			if yamlConfig.MitmConfig.HttpDump.FlagReq && yamlConfig.MitmConfig.HttpDump.DumpRequest {
				rawReqWithoutBody, _ := httputil.DumpRequestOut(ctx.Req, false)
				rawReqBody, _ := ioutil.ReadAll(bufio.NewReader(ctx.Req.Body))
				ctx.Req.Body = ioutil.NopCloser(bytes.NewReader(rawReqBody))
				yamlConfig.MitmConfig.HttpDump.RequestHeader = string(rawReqWithoutBody)
				yamlConfig.MitmConfig.HttpDump.RequestBody = string(rawReqBody)
			}
		}
	}
	// 取出在connect中保存的数据
	// ctx.Req.Header.Add("X-Request-Id", ctx.Data["req_id"].(string))
	// 设置X-Forwarded-For
	// if clientIP, _, err := net.SplitHostPort(ctx.Req.RemoteAddr); err == nil {
	// 	if prior, ok := ctx.Req.Header["X-Forwarded-For"]; ok {
	// 		clientIP = strings.Join(prior, ", ") + ", " + clientIP
	// 	}
	// 	ctx.Req.Header.Set("X-Forwarded-For", clientIP)
	// }

}

// func getTimestamp() string {
//     return strconv.FormatInt(time.Now().Local().UnixNano()/1e6, 10)
// }

func (e *EventHandler) BeforeResponse(ctx *goproxy.Context, resp *http.Response, err error) {
	// fmt.Printf("BeforeResponse to: %s \n", ctx.Req.URL.Host)
	if resp == nil {
		ctx.Abort()
		log.Println("resp is nil")
		return
	}

	// rawResp, _ := httputil.DumpResponse(resp, true)
	// log.Println(string(rawResp))

	if yamlConfig.MitmConfig.Restriction.FlagRestriction {
		if yamlConfig.MitmConfig.HttpDump.DumpPath != "" {
			fileObj, err := os.OpenFile(yamlConfig.MitmConfig.HttpDump.DumpPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, os.ModeAppend|os.ModePerm) // 读写方式打开
			if err != nil {
				log.Println(err)
			}
			defer fileObj.Close()
			if err == nil && yamlConfig.MitmConfig.HttpDump.FlagReq && yamlConfig.MitmConfig.HttpDump.DumpResponse {
				yamlConfig.MitmConfig.HttpDump.FlagResp = config.CheckRespConditions(resp, yamlConfig.MitmConfig.HttpDump.Conditions)
				if yamlConfig.MitmConfig.HttpDump.FlagResp {
					rawRespWithoutBody, _ := httputil.DumpResponse(resp, false)
					// log.Println(string(rawRespWithoutBody))
					var rawRespBody []byte
					switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
					case "gzip":
						rawRespBody, _ = utils.GZIPDe(resp.Body)
						resp.Body = ioutil.NopCloser(bytes.NewBuffer(utils.GZIPEn(string(rawRespBody))))
					case "br":
						rawRespBody, _ = utils.BRDe(resp.Body)
						resp.Body = ioutil.NopCloser(bytes.NewBuffer(utils.BREn(string(rawRespBody))))
					default:
						rawRespBody, _ = ioutil.ReadAll(resp.Body)
						resp.Body = ioutil.NopCloser(bytes.NewReader(rawRespBody))
					}
					yamlConfig.MitmConfig.HttpDump.ResponseHeader = string(rawRespWithoutBody)
					yamlConfig.MitmConfig.HttpDump.ResponseBody = string(rawRespBody)

					// log.Println(string(yamlConfig.MitmConfig.HttpDump.RequestHeader + yamlConfig.MitmConfig.HttpDump.RequestBody))
					// log.Println(string(yamlConfig.MitmConfig.HttpDump.ResponseHeader + yamlConfig.MitmConfig.HttpDump.ResponseBody))

					if yamlConfig.MitmConfig.HttpDump.DumpRequest {
						fileObj.WriteString("```\n" + yamlConfig.MitmConfig.HttpDump.RequestHeader + yamlConfig.MitmConfig.HttpDump.RequestBody + "\n```\n")
					}
					fileObj.WriteString("```\n" + yamlConfig.MitmConfig.HttpDump.ResponseHeader + yamlConfig.MitmConfig.HttpDump.ResponseBody + "\n```\n")
				}
			}
		}

		tmpResp := resp
		for i, v := range yamlConfig.MitmConfig.CustomReplaces {
			// log.Println(yamlConfig.MitmConfig.CustomReplaces[i].FlagReq)
			if yamlConfig.MitmConfig.CustomReplaces[i].FlagReq {
				// log.Println(yamlConfig.MitmConfig.CustomReplaces[i].FlagResp)
				yamlConfig.MitmConfig.CustomReplaces[i].FlagResp = config.CheckRespConditions(tmpResp, v.Conditions)
				// log.Println(yamlConfig.MitmConfig.CustomReplaces[i].FlagResp)
				tmpResp, _ = config.DoRespReplace(tmpResp, v.Replaces)
			}
		}

		resp.Status = tmpResp.Status
		resp.StatusCode = tmpResp.StatusCode
		resp.Proto = tmpResp.Proto
		resp.ProtoMajor = tmpResp.ProtoMajor
		resp.ProtoMinor = tmpResp.ProtoMinor
		resp.Header = goproxy.CloneHeader(tmpResp.Header)
		resp.Body, _, _ = goproxy.CloneBody(tmpResp.Body)
		// resp.Header = tmpResp.Header
		// resp.Body = tmpResp.Body
		resp.ContentLength = tmpResp.ContentLength
		resp.TransferEncoding = tmpResp.TransferEncoding
		resp.Trailer = tmpResp.Trailer
		resp.Request = tmpResp.Request
		resp.TLS = tmpResp.TLS
	}

	// Status     string // e.g. "200 OK"
	// StatusCode int    // e.g. 200
	// Proto      string // e.g. "HTTP/1.0"
	// ProtoMajor int    // e.g. 1
	// ProtoMinor int    // e.g. 0
	// Header Header
	// Body io.ReadCloser
	// ContentLength int64
	// TransferEncoding []string
	// Close bool
	// Uncompressed bool
	// Trailer Header
	// Request *Request
	// TLS *tls.ConnectionState

	if err != nil {
		return
	}
	// 修改response
}

// 设置上级代理
func (e *EventHandler) ParentProxy(req *http.Request) (*url.URL, error) {
	// fmt.Println("Parent Proxy")
	if yamlConfig.MitmConfig.UpstreamProxy == "" {
		return nil, nil
	} else {
		return url.Parse(yamlConfig.MitmConfig.UpstreamProxy)
	}
}

func (e *EventHandler) Finish(ctx *goproxy.Context) {
	// fmt.Printf("请求结束 URL:%s\n", ctx.Req.URL)
}

// 记录错误日志
func (e *EventHandler) ErrorLog(err error) {
	log.Println(err)
}
