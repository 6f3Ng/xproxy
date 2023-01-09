package global

import (
	"xproxy/config"
)

var (
	YamlConfigVar config.YamlConfig
	ConfigFile    string
	ListenAddr    string
	GenerateCA    bool
	IpLists       []string
)

// func init() {
// 	IpList, _ = utils.GetAllIps()
// }
