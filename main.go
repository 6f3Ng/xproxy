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
	"xproxy/global"
	"xproxy/goproxy"
	"xproxy/utils"
)

// var (
// 	global.ConfigFile string
// 	global.ListenAddr string
// 	global.GenerateCA bool
// )

// 初始化
func init() {
	log.Println("开始初始化...")
	flag.StringVar(&global.ConfigFile, "config", "config.yaml", "yaml config file, default \"config.yaml\"")
	flag.StringVar(&global.ListenAddr, "listen", ":8082", "listen addr, default \":8082\"")
	flag.BoolVar(&global.GenerateCA, "GenerateCA", false, "generate ca_cert and ca_key")
	testing.Init()
	flag.Parse()
	if _, err := os.Stat(global.ConfigFile); err != nil {
		log.Println("指定的配置文件" + global.ConfigFile + "不存在，准备调用默认配置文件config.yaml...")
		global.ConfigFile = "config.yaml"
	}
	// 读取config.yaml文件，读取失败则初始化一个
	err := global.YamlConfigVar.Load(global.ConfigFile, &global.YamlConfigVar)
	// log.Println(global.YamlConfigVar)
	if err != nil || global.YamlConfigVar.IsEmpty() {
		global.YamlConfigVar.Init(global.ConfigFile)
	}

	if global.GenerateCA {
		keyPair, err := cert.GenerateCA()
		if err != nil {
			log.Fatalf("证书生成失败: %s", err)
		}
		err = ioutil.WriteFile(global.YamlConfigVar.MitmConfig.CaCert, keyPair.CertBytes, os.ModeAppend|os.ModePerm)
		if err != nil {
			log.Fatalf("根证书写入失败: %s", err)
		}
		err = ioutil.WriteFile(global.YamlConfigVar.MitmConfig.CaKey, keyPair.PrivateKeyBytes, os.ModeAppend|os.ModePerm)
		if err != nil {
			log.Fatalf("根证书私钥写入失败: %s", err)
		}
		log.Fatalln("证书生成成功！")
	}

	log.Println("读取证书...")
	cert.Init(global.YamlConfigVar.MitmConfig.CaCert, global.YamlConfigVar.MitmConfig.CaKey)

	global.IpLists, _ = utils.GetAllIps()

	log.Println("初始化完成！")
}

func main() {
	proxy := goproxy.New(goproxy.WithDelegate(&EventHandler{}), goproxy.WithDecryptHTTPS(&Cache{}))
	server := &http.Server{
		Addr:         global.ListenAddr,
		Handler:      proxy,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}
	err := server.ListenAndServe()
	// err := server.ListenAndServeTLS(global.YamlConfigVar.MitmConfig.CaCert, global.YamlConfigVar.MitmConfig.CaKey)
	if err != nil {
		panic(err)
	}
}
