package main

import (
	"fmt"
	"testing"
	"xproxy/utils"
)

func TestIsMatchHost(t *testing.T) {
	fmt.Println(utils.IsMatchHost("192.168.1.3", "192.168.1.2-5"))
}

func TestIsMatchString(t *testing.T) {
	fmt.Println(utils.IsMatchString("ug.baidu.com", "*.baidu.com"))
}

func TestIsMatchPort(t *testing.T) {
	fmt.Println(utils.IsMatchPort("80", "80-89"))
}
