package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"xproxy/cert"
	"xproxy/config"
	"xproxy/goproxy"
)

var (
	configFile string
	listenAddr string
	yamlConfig config.YamlConfig
)

// 初始化
func init() {
	log.Println("开始初始化...")
	flag.StringVar(&configFile, "config", "config.yaml", "yaml config file, default \"config.yaml\"")
	flag.StringVar(&listenAddr, "listen", ":8082", "listen addr, default \":8082\"")
	testing.Init()
	flag.Parse()
	if _, err := os.Stat(configFile); err != nil {
		log.Println("指定的配置文件" + configFile + "不存在，准备调用默认配置文件config.yaml...")
		configFile = "config.yaml"
	}
	// 读取config.yaml文件，读取失败则初始化一个
	err := yamlConfig.Load(configFile, &yamlConfig)
	// log.Println(yamlConfig)
	if err != nil || yamlConfig.IsEmpty() {
		yamlConfig.Init(configFile)
	}

	log.Println("读取证书...")
	cert.Init(yamlConfig.MitmConfig.CaCert, yamlConfig.MitmConfig.CaKey)

	log.Println("初始化完成！")
}

func main() {
	proxy := goproxy.New(goproxy.WithDelegate(&EventHandler{}), goproxy.WithDecryptHTTPS(&Cache{}))
	server := &http.Server{
		Addr:         listenAddr,
		Handler:      proxy,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
