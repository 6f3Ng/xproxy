package config

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"xproxy/goproxy"
	"xproxy/utils"
)

// 匹配返回true；未匹配返回false，禁止访问
func CheckAllowIpRange(ip string, allowIpRange []string) bool {
	if len(allowIpRange) > 0 {
		for _, v := range allowIpRange {
			if utils.IsMatchHost(ip, v) {
				return true
			}
		}
		return false
	}
	return true
}

// 匹配restriction，匹配成功返回true，进行后续替换操作；未匹配返回false
func CheckRestriction(ctx *goproxy.Context, restriction Restriction) bool {
	queryKeys := []string{}
	postKeys := []string{}
	for k := range ctx.Req.URL.Query() {
		queryKeys = append(queryKeys, k)
	}
	for k := range ctx.Req.PostForm {
		postKeys = append(postKeys, k)
	}
	var (
		hostIp   string
		hostPort string
	)
	if strings.Contains(ctx.Req.Host, ":") {
		hostIp, hostPort, _ = net.SplitHostPort(ctx.Req.Host)
	} else {
		hostIp = ctx.Req.Host
		if ctx.Req.TLS == nil {
			hostPort = "80"
		} else {
			hostPort = "443"
		}
	}
	// log.Println(ctx.Req.URL.Path)

	return checkHostname(hostIp, restriction.HostnameAllowed, restriction.HostnameDisallowed) &&
		checkPort(hostPort, restriction.PortAllowed, restriction.PortDisallowed) &&
		checkString(ctx.Req.URL.Path, restriction.PathAllowed, restriction.PathDisallowed) &&
		checkArray(queryKeys, restriction.QueryKeyAllowed, restriction.QueryKeyDisallowed) &&
		checkArray(postKeys, restriction.PostKeyAllowed, restriction.PostKeyDisallowed) &&
		checkString(ctx.Req.URL.Fragment, restriction.FragmentAllowed, restriction.FragmentDisallowed)
}

// 判断custom_replace中关于request的条件是否成立
func CheckReqConditions(ctx *goproxy.Context, condition []Condition) bool {
	rawReq, err := httputil.DumpRequestOut(ctx.Req, true)
	if err != nil {
		log.Panicln(err)
	}
	// log.Println(string(rawReq))
	rawReqWithoutBody, _ := httputil.DumpRequestOut(ctx.Req, false)
	// log.Println(string(rawReqWithoutBody))
	rawReqBody, _ := ioutil.ReadAll(bufio.NewReader(ctx.Req.Body))
	ctx.Req.Body = ioutil.NopCloser(bytes.NewReader(rawReqBody))
	// log.Println(string(rawReqBody))

	for _, v := range condition {
		switch v.Item {
		case "request_header":
			if v.Regexp {
				if !utils.IsContainRegexp(string(rawReqWithoutBody), v.Match) {
					return false
				}
			} else {
				if !utils.IsContainString(string(rawReqWithoutBody), v.Match) {
					return false
				}
			}
		case "request_body":
			if v.Regexp {
				if !utils.IsContainRegexp(string(rawReqBody), v.Match) {
					return false
				}
			} else {
				if !utils.IsContainString(string(rawReqBody), v.Match) {
					return false
				}
			}
		case "response_header":
			continue
		case "response_body":
			continue
		case "request_param_name":
			continue
		case "request_param_value":
			continue
		default:
			if v.Regexp {
				if !utils.IsContainRegexp(string(rawReq), v.Match) {
					return false
				}
			} else {
				if !utils.IsContainString(string(rawReq), v.Match) {
					return false
				}
			}
		}
	}
	return true
}

// 判断custom_replace中关于response的条件是否成立
func CheckRespConditions(resp *http.Response, condition []Condition) bool {
	rawResp, _ := httputil.DumpResponse(resp, true)
	// log.Println(string(rawResp))
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
	// log.Println(string(rawRespBody))

	for _, v := range condition {
		switch v.Item {
		case "request_header":
			continue
		case "request_body":
			continue
		case "response_header":
			if v.Regexp {
				if !utils.IsContainRegexp(string(rawRespWithoutBody), v.Match) {
					return false
				}
			} else {
				if !utils.IsContainString(string(rawRespWithoutBody), v.Match) {
					return false
				}
			}
		case "response_body":
			if v.Regexp {
				if !utils.IsContainRegexp(string(rawRespBody), v.Match) {
					return false
				}
			} else {
				if !utils.IsContainString(string(rawRespBody), v.Match) {
					return false
				}
			}
		case "request_param_name":
			continue
		case "request_param_value":
			continue
		default:
			if v.Regexp {
				if !utils.IsContainRegexp(string(rawResp), v.Match) {
					return false
				}
			} else {
				if !utils.IsContainString(string(rawResp), v.Match) {
					return false
				}
			}
		}
	}
	return true
}

// 对custom_replace中关于request的条件进行替换
func DoReqReplace(ctx *goproxy.Context, replace []Replace) (*http.Request, error) {
	rawReqWithoutBody, _ := httputil.DumpRequestOut(ctx.Req, false)
	// log.Println(string(rawReqWithoutBody))
	rawReqBody, _ := ioutil.ReadAll(bufio.NewReader(ctx.Req.Body))
	// log.Println(string(rawReqBody))

	for _, v := range replace {
		switch v.Item {
		case "request_header":
			if v.Regexp {
				// reqHeaderRegexpReplace()
				re, _ := regexp.Compile(v.Match)
				rawReqWithoutBody = re.ReplaceAll(rawReqWithoutBody, []byte(v.Replace))
			} else {
				rawReqWithoutBody = []byte(bytes.ReplaceAll(rawReqWithoutBody, []byte(v.Match), []byte(v.Replace)))
			}
		case "request_body":
			if v.Regexp {
				re, _ := regexp.Compile(v.Match)
				rawReqBody = re.ReplaceAll(rawReqBody, []byte(v.Replace))
			} else {
				rawReqBody = []byte(bytes.ReplaceAll(rawReqBody, []byte(v.Match), []byte(v.Replace)))
			}
		case "response_header":
			continue
		case "response_body":
			continue
		case "request_param_name":
			continue
		case "request_param_value":
			continue
		default:
			if v.Regexp {
				re, _ := regexp.Compile(v.Match)
				rawReqWithoutBody = re.ReplaceAll(rawReqWithoutBody, []byte(v.Replace))
				rawReqBody = re.ReplaceAll(rawReqBody, []byte(v.Replace))
			} else {
				rawReqWithoutBody = []byte(bytes.ReplaceAll(rawReqWithoutBody, []byte(v.Match), []byte(v.Replace)))
				rawReqBody = []byte(bytes.ReplaceAll(rawReqBody, []byte(v.Match), []byte(v.Replace)))
			}
		}
	}
	newReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(append(rawReqWithoutBody, rawReqBody...))))
	newReq.URL.Scheme = ctx.Req.URL.Scheme
	newReq.URL.Host = ctx.Req.URL.Host
	return newReq, err
}

// 对custom_replace中关于response的条件进行替换
func DoRespReplace(resp *http.Response, replace []Replace) (*http.Response, error) {
	rawRespWithoutBody, _ := httputil.DumpResponse(resp, false)
	// log.Println(string(rawRespWithoutBody))
	var rawRespBody []byte
	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "gzip":
		rawRespBody, _ = utils.GZIPDe(resp.Body)
	case "br":
		rawRespBody, _ = utils.BRDe(resp.Body)
	default:
		rawRespBody, _ = ioutil.ReadAll(resp.Body)
	}

	for _, v := range replace {
		switch v.Item {
		case "request_header":
			continue
		case "request_body":
			continue
		case "response_header":
			if v.Regexp {
				// reqHeaderRegexpReplace()
				re, _ := regexp.Compile(v.Match)
				rawRespWithoutBody = re.ReplaceAll(rawRespWithoutBody, []byte(v.Replace))
			} else {
				rawRespWithoutBody = []byte(bytes.ReplaceAll(rawRespWithoutBody, []byte(v.Match), []byte(v.Replace)))
			}
		case "response_body":
			if v.Regexp {
				re, _ := regexp.Compile(v.Match)
				rawRespBody = re.ReplaceAll(rawRespBody, []byte(v.Replace))
			} else {
				rawRespBody = []byte(bytes.ReplaceAll(rawRespBody, []byte(v.Match), []byte(v.Replace)))
			}
		case "request_param_name":
			continue
		case "request_param_value":
			continue
		default:
			if v.Regexp {
				re, _ := regexp.Compile(v.Match)
				rawRespWithoutBody = re.ReplaceAll(rawRespWithoutBody, []byte(v.Replace))
				rawRespBody = re.ReplaceAll(rawRespBody, []byte(v.Replace))
			} else {
				rawRespWithoutBody = []byte(bytes.ReplaceAll(rawRespWithoutBody, []byte(v.Match), []byte(v.Replace)))
				rawRespBody = []byte(bytes.ReplaceAll(rawRespBody, []byte(v.Match), []byte(v.Replace)))
			}
		}
	}
	resp, _ = http.ReadResponse(bufio.NewReader(bytes.NewReader(rawRespWithoutBody)), resp.Request)
	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "gzip":
		rawRespBody = utils.GZIPEn(string(rawRespBody))
		resp.ContentLength = int64(len(rawRespBody))
		resp.Body = ioutil.NopCloser(bytes.NewBuffer(rawRespBody))
	case "br":
		rawRespBody = utils.BREn(string(rawRespBody))
		resp.ContentLength = int64(len(rawRespBody))
		resp.Body = ioutil.NopCloser(bytes.NewBuffer(rawRespBody))
	default:
		resp.ContentLength = int64(len(rawRespBody))
		resp.Body = ioutil.NopCloser(bytes.NewReader(rawRespBody))
	}

	return resp, nil
}

// 判断hostname的条件是否成立
func checkHostname(s string, allowed, disallowd []string) bool {
	if len(allowed) != 0 {
		for _, v := range allowed {
			if utils.IsMatchHost(s, v) {
				return true
			}
		}
		return false
	}
	if len(disallowd) != 0 {
		for _, v := range disallowd {
			if utils.IsMatchHost(s, v) {
				return false
			}
		}
	}
	return true

}

// 判断port的条件是否成立
func checkPort(s string, allowed, disallowd []string) bool {
	if len(allowed) != 0 {
		for _, v := range allowed {
			if utils.IsMatchPort(s, v) {
				return true
			}
		}
		return false
	}
	if len(disallowd) != 0 {
		for _, v := range disallowd {
			if utils.IsMatchPort(s, v) {
				return false
			}
		}
	}
	return true

}

func checkString(s string, allowed, disallowd []string) bool {
	if len(allowed) != 0 {
		for _, v := range allowed {
			if utils.IsMatchString(s, v) {
				return true
			}
		}
		return false
	}
	if len(disallowd) != 0 {
		for _, v := range disallowd {
			if utils.IsMatchString(s, v) {
				return false
			}
		}
	}
	return true

}

func checkArray(a []string, allowed, disallowd []string) bool {
	if len(allowed) != 0 {
		for _, ak := range a {
			for _, v := range allowed {
				if !utils.IsMatchString(ak, v) {
					return false
				}
			}
		}
		return true
	}
	if len(disallowd) != 0 {
		for _, ak := range a {
			for _, v := range disallowd {
				if utils.IsMatchString(ak, v) {
					return false
				}
			}
		}
	}
	return true
}
