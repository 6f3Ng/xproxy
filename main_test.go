package main

import (
	"fmt"
	"net"
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

func TestIps(t *testing.T) {
	getAllIps()
}

func getAllIps() ([]string, error) {
	ips := []string{}
	interfaces, err := net.Interfaces()

	if err != nil {
		return nil, err
	}

	for _, i := range interfaces {
		if err != nil {
			return nil, err
		}
		addresses, _ := i.Addrs()
		for _, address := range addresses {
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					fmt.Println(ipnet.IP.String())
					ips = append(ips, ipnet.IP.String())
				}
			}
		}
	}
	return ips, nil
}
