package goproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"xproxy/cert"
	"xproxy/global"
)

func index(ctx *Context, rw http.ResponseWriter) {
	sendHTMLResponse(rw, []byte("<a href=\"/downloadCert\">downloadCert</a>"))
}

func getConfig(ctx *Context, rw http.ResponseWriter) {
	sendJSONResponse(rw, global.YamlConfigVar)
}

// 下载证书
func downloadCert(ctx *Context, rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "application/octet-stream; charset=UTF-8")
	rw.Header().Set("Content-Disposition", "attachment; filename="+global.YamlConfigVar.MitmConfig.CaCert)
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	rw.Header().Add("Access-Control-Allow-Headers", "Content-Type")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     http.StatusText(http.StatusOK),
		Body:       ioutil.NopCloser(bytes.NewBuffer(cert.GetDefaultRootCAPem())),
	}

	removeConnectionHeaders(resp.Header)
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}

	defer resp.Body.Close()
	CopyHeader(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	io.Copy(rw, resp.Body)
}

func sendHTMLResponse(rw http.ResponseWriter, data []byte) {
	rw.Header().Set("Content-Type", "text/html; charset=UTF-8")
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	rw.Header().Add("Access-Control-Allow-Headers", "Content-Type")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     http.StatusText(http.StatusOK),
		Body:       ioutil.NopCloser(bytes.NewBuffer(data)),
	}

	removeConnectionHeaders(resp.Header)
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}

	defer resp.Body.Close()
	CopyHeader(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	io.Copy(rw, resp.Body)
}

// func sendTextResponse(rw http.ResponseWriter, data []byte) {
// 	rw.Header().Set("Content-Type", "text/plain; charset=UTF-8")
// 	rw.Header().Set("Access-Control-Allow-Origin", "*")
// 	rw.Header().Add("Access-Control-Allow-Headers", "Content-Type")
// 	resp := &http.Response{
// 		StatusCode: http.StatusOK,
// 		Status:     http.StatusText(http.StatusOK),
// 		Body:       ioutil.NopCloser(bytes.NewBuffer(data)),
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

func sendJSONResponse(rw http.ResponseWriter, data interface{}) {
	rw.Header().Set("Content-Type", "application/json;text/plain; charset=UTF-8")
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	rw.Header().Add("Access-Control-Allow-Headers", "Content-Type")
	body, err := json.Marshal(data)
	if err != nil {
		//logger.Println("Failed to encode a JSON response: ", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     http.StatusText(http.StatusOK),
		Body:       ioutil.NopCloser(bytes.NewBuffer(body)),
	}

	removeConnectionHeaders(resp.Header)
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}

	defer resp.Body.Close()
	CopyHeader(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	io.Copy(rw, resp.Body)
}
