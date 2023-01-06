package main

import (
	"flag"
	"io/ioutil"
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
	generateCA bool
	yamlConfig config.YamlConfig
)

// 初始化
func init() {
	log.Println("开始初始化...")
	flag.StringVar(&configFile, "config", "config.yaml", "yaml config file, default \"config.yaml\"")
	flag.StringVar(&listenAddr, "listen", ":8082", "listen addr, default \":8082\"")
	flag.BoolVar(&generateCA, "generateCA", false, "generate ca_cert and ca_key")
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

	if generateCA {
		keyPair, err := cert.GenerateCA()
		if err != nil {
			log.Fatalf("证书生成失败: %s", err)
		}
		err = ioutil.WriteFile(yamlConfig.MitmConfig.CaCert, keyPair.CertBytes, os.ModeAppend|os.ModePerm)
		if err != nil {
			log.Fatalf("根证书写入失败: %s", err)
		}
		err = ioutil.WriteFile(yamlConfig.MitmConfig.CaKey, keyPair.PrivateKeyBytes, os.ModeAppend|os.ModePerm)
		if err != nil {
			log.Fatalf("根证书私钥写入失败: %s", err)
		}
		log.Fatalln("证书生成成功！")
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
	// err := server.ListenAndServeTLS(yamlConfig.MitmConfig.CaCert, yamlConfig.MitmConfig.CaKey)
	if err != nil {
		panic(err)
	}
}
