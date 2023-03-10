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
	"xproxy/global"
	"xproxy/goproxy"
	"xproxy/utils"
)

type EventHandler struct{}

func (e *EventHandler) Connect(ctx *goproxy.Context, rw http.ResponseWriter) {
	// fmt.Printf("connect to: %s \n", ctx.Req.URL)
	// 保存的数据可以在后面的回调方法中获取
	// ctx.Data["req_id"] = "uuid"

	// 是否在allow_ip_range中，否则禁止访问
	if !config.CheckAllowIpRange(ctx.Req.RemoteAddr, global.YamlConfigVar.MitmConfig.AllowIpRange) {
		ctx.Abort()
		return
	}

	// 初始化一些标志位
	// global.YamlConfigVar.MitmConfig.RawData.RequestHeader = ""
	// global.YamlConfigVar.MitmConfig.RawData.RequestBody = ""
	// global.YamlConfigVar.MitmConfig.RawData.ResponseHeader = ""
	// global.YamlConfigVar.MitmConfig.RawData.ResponseBody = ""

	// 禁止访问某个域名
	// if strings.Contains(ctx.Req.URL.Host, "example.com") {
	//     rw.WriteHeader(http.StatusForbidden)
	//     ctx.Abort()
	//     return
	// }
}

func (e *EventHandler) Auth(ctx *goproxy.Context, rw http.ResponseWriter) {
	// fmt.Printf("auth to: %s \n", ctx.Req.URL)

	if global.YamlConfigVar.MitmConfig.BasicAuth.Username != "" {
		authString := ctx.Req.Header.Get("Proxy-Authorization")
		if authString == "" {
			ctx.Abort()
			return
		}
		user, pass, ok := parseBasicAuth(authString)
		if !ok || user != global.YamlConfigVar.MitmConfig.BasicAuth.Username || pass != global.YamlConfigVar.MitmConfig.BasicAuth.Password {
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

	global.YamlConfigVar.MitmConfig.Restriction.FlagRestriction = config.CheckRestriction(ctx.Req, global.YamlConfigVar.MitmConfig.Restriction)
	// 修改header

	rawReqWithoutBody, _ := httputil.DumpRequestOut(ctx.Req, false)
	rawReqBody, _ := ioutil.ReadAll(bufio.NewReader(ctx.Req.Body))
	ctx.Req.Body = ioutil.NopCloser(bytes.NewReader(rawReqBody))
	global.YamlConfigVar.MitmConfig.RawData.RequestHeader = string(rawReqWithoutBody)
	global.YamlConfigVar.MitmConfig.RawData.RequestBody = string(rawReqBody)

	if global.YamlConfigVar.MitmConfig.Restriction.FlagRestriction {
		for k, v := range global.YamlConfigVar.MitmConfig.CustomHeader.Reset {
			ctx.Req.Header.Set(k, v)
		}
		for k, v := range global.YamlConfigVar.MitmConfig.CustomHeader.Add {
			if prior, ok := ctx.Req.Header[k]; ok {
				prior = append(prior, v)
				newPrior := strings.Join(prior, "")
				ctx.Req.Header.Set(k, newPrior)
			} else {
				ctx.Req.Header.Set(k, v)
			}
		}
		for _, v := range global.YamlConfigVar.MitmConfig.CustomHeader.Delete {
			ctx.Req.Header.Del(v)
		}
		for i, v := range global.YamlConfigVar.MitmConfig.CustomReplaces {
			global.YamlConfigVar.MitmConfig.CustomReplaces[i].FlagReq = config.CheckReqConditions(ctx.Req, v.Conditions)
			// log.Println(v.FlagReq)
			if global.YamlConfigVar.MitmConfig.CustomReplaces[i].FlagReq {
				ctx.Req, _ = config.DoReqReplace(ctx.Req, v.Replaces)
			}
		}
		if global.YamlConfigVar.MitmConfig.HttpDump.DumpPath != "" {
			global.YamlConfigVar.MitmConfig.HttpDump.FlagReq = config.CheckReqConditions(ctx.Req, global.YamlConfigVar.MitmConfig.HttpDump.Conditions)
			if global.YamlConfigVar.MitmConfig.HttpDump.FlagReq && global.YamlConfigVar.MitmConfig.HttpDump.DumpRequest {
				rawReqWithoutBody, _ := httputil.DumpRequestOut(ctx.Req, false)
				rawReqBody, _ := ioutil.ReadAll(bufio.NewReader(ctx.Req.Body))
				ctx.Req.Body = ioutil.NopCloser(bytes.NewReader(rawReqBody))
				global.YamlConfigVar.MitmConfig.RawData.RequestHeader = string(rawReqWithoutBody)
				global.YamlConfigVar.MitmConfig.RawData.RequestBody = string(rawReqBody)
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

	if global.YamlConfigVar.MitmConfig.Restriction.FlagRestriction {
		if global.YamlConfigVar.MitmConfig.HttpDump.DumpPath != "" {
			fileObj, err := os.OpenFile(global.YamlConfigVar.MitmConfig.HttpDump.DumpPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, os.ModeAppend|os.ModePerm) // 读写方式打开
			if err != nil {
				log.Println(err)
			}
			defer fileObj.Close()
			if err == nil && global.YamlConfigVar.MitmConfig.HttpDump.FlagReq && global.YamlConfigVar.MitmConfig.HttpDump.DumpResponse {
				global.YamlConfigVar.MitmConfig.HttpDump.FlagResp = config.CheckRespConditions(resp, global.YamlConfigVar.MitmConfig.HttpDump.Conditions)
				if global.YamlConfigVar.MitmConfig.HttpDump.FlagResp {
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
					global.YamlConfigVar.MitmConfig.RawData.ResponseHeader = string(rawRespWithoutBody)
					global.YamlConfigVar.MitmConfig.RawData.ResponseBody = string(rawRespBody)

					// log.Println(string(global.YamlConfigVar.MitmConfig.RawData.RequestHeader + global.YamlConfigVar.MitmConfig.RawData.RequestBody))
					// log.Println(string(global.YamlConfigVar.MitmConfig.RawData.ResponseHeader + global.YamlConfigVar.MitmConfig.RawData.ResponseBody))

				}
			}
			if err == nil && global.YamlConfigVar.MitmConfig.HttpDump.FlagReq && global.YamlConfigVar.MitmConfig.HttpDump.DumpRequest {
				fileObj.WriteString("```\n" + global.YamlConfigVar.MitmConfig.RawData.RequestHeader + global.YamlConfigVar.MitmConfig.RawData.RequestBody + "\n```\n")
			}
			if err == nil && global.YamlConfigVar.MitmConfig.HttpDump.FlagResp && global.YamlConfigVar.MitmConfig.HttpDump.DumpResponse {
				fileObj.WriteString("```\n" + global.YamlConfigVar.MitmConfig.RawData.ResponseHeader + global.YamlConfigVar.MitmConfig.RawData.ResponseBody + "\n```\n")
			}
		}

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
		global.YamlConfigVar.MitmConfig.RawData.ResponseHeader = string(rawRespWithoutBody)
		global.YamlConfigVar.MitmConfig.RawData.ResponseBody = string(rawRespBody)

		tmpResp := resp
		for i, v := range global.YamlConfigVar.MitmConfig.CustomReplaces {
			// log.Println(global.YamlConfigVar.MitmConfig.CustomReplaces[i].FlagReq)
			if global.YamlConfigVar.MitmConfig.CustomReplaces[i].FlagReq {
				// log.Println(global.YamlConfigVar.MitmConfig.CustomReplaces[i].FlagResp)
				global.YamlConfigVar.MitmConfig.CustomReplaces[i].FlagResp = config.CheckRespConditions(tmpResp, v.Conditions)
				// log.Println(global.YamlConfigVar.MitmConfig.CustomReplaces[i].FlagResp)
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
	if global.YamlConfigVar.MitmConfig.UpstreamProxy == "" {
		return nil, nil
	} else {
		return url.Parse(global.YamlConfigVar.MitmConfig.UpstreamProxy)
	}
}

func (e *EventHandler) Finish(ctx *goproxy.Context) {
	// fmt.Printf("请求结束 URL:%s\n", ctx.Req.URL)
}

// 记录错误日志
func (e *EventHandler) ErrorLog(err error) {
	log.Println(err)
}
