package config

import (
	"io/ioutil"
	"os"
	"reflect"

	"gopkg.in/yaml.v2"
)

var YamlConfigVar YamlConfig

type YamlConfig struct {
	MitmConfig MitmConfig `yaml:"mitm"`
}

type MitmConfig struct {
	CaCert         string          `yaml:"ca_cert"`        // CA 根证书路径
	CaKey          string          `yaml:"ca_key"`         // CA 私钥路径
	BasicAuth      BasicAuth       `yaml:"basic_auth"`     // 基础认证的用户名密码
	AllowIpRange   []string        `yaml:"allow_ip_range"` // 允许的 ip，可以是 ip 或者 cidr 字符串
	Restriction    Restriction     `yaml:"restriction"`    // 代理能够访问的资源限制, 以下各项为空表示不限制
	Queue          Queue           `yaml:"queue"`          // （暂不支持）队列长度限制, 也可以理解为最大允许多少等待扫描的请求, 请根据内存大小自行调整
	ProxyHeader    ProxyHeader     `yaml:"proxy_header"`   // 代理请求头
	UpstreamProxy  string          `yaml:"upstream_proxy"` // 为 mitm 本身配置独立的代理，[http|https|socks5]://user:pass@localhost.com，如果格式错误会导致无法使用
	CustomHeader   CustomHeader    `yaml:"custom_header"`  // 定义只对restriction中allow的设置生效
	CustomReplaces []CustomReplace `yaml:"custom_replace"` // 定义只对restriction中allow的设置生效（注：conditions设置response相关匹配条件对request的替换不生效）
	HttpDump       HttpDump        `yaml:"http_dump"`      // 保存http数据包，request数据包在自定义替换后保存，response数据包在自定义替换前保存
	RawData        RawData         `yaml:"-"`
}
type RawData struct {
	RequestHeader  string `yaml:"-"` // 临时保存request header原文
	RequestBody    string `yaml:"-"` // 临时保存request body原文
	ResponseHeader string `yaml:"-"` // 临时保存request header原文
	ResponseBody   string `yaml:"-"` // 临时保存request body原文

}

type BasicAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Restriction struct {
	HostnameAllowed    []string `yaml:"hostname_allowed"`     // 允许访问的 Hostname，支持格式如 t.com、*.t.com、1.1.1.1、1.1.1.1/24、1.1-4.1.1-8
	HostnameDisallowed []string `yaml:"hostname_disallowed"`  // 不允许访问的 Hostname，支持格式如 t.com、*.t.com、1.1.1.1、1.1.1.1/24、1.1-4.1.1-8
	PortAllowed        []string `yaml:"port_allowed"`         // 允许访问的端口, 支持的格式如: 80、80-85
	PortDisallowed     []string `yaml:"port_disallowed"`      // 不允许访问的端口, 支持的格式如: 80、80-85
	PathAllowed        []string `yaml:"path_allowed"`         // 允许访问的路径，支持的格式如: test、*test*
	PathDisallowed     []string `yaml:"path_disallowed"`      // 不允许访问的路径, 支持的格式如: test、*test*
	QueryKeyAllowed    []string `yaml:"query_key_allowed"`    // 允许访问的 Query Key，支持的格式如: test、*test*
	QueryKeyDisallowed []string `yaml:"query_key_disallowed"` // 不允许访问的 Query Key, 支持的格式如: test、*test*
	FragmentAllowed    []string `yaml:"fragment_allowed"`     // 允许访问的 Fragment, 支持的格式如: test、*test*
	FragmentDisallowed []string `yaml:"fragment_disallowed"`  // 不允许访问的 Fragment, 支持的格式如: test、*test*
	PostKeyAllowed     []string `yaml:"post_key_allowed"`     // 允许访问的 Post Body 中的参数, 支持的格式如: test、*test*
	PostKeyDisallowed  []string `yaml:"post_key_disallowed"`  // 不允许访问的 Post Body 中的参数, 支持的格式如: test、*test*
	FlagRestriction    bool     `yaml:"-" json:"-"`           // Restriction的匹配结果，后续调用
}

type Queue struct {
	MaxLength int `yaml:"max_length"` // 队列长度限制, 也可以理解为最大允许多少等待扫描的请求, 请根据内存大小自行调整
}

type ProxyHeader struct {
	Via        string `yaml:"via"`         // 是否为代理自动添加 Via 头
	XForwarded bool   `yaml:"x_forwarded"` // 是否为代理自动添加 X-Forwarded-{For,Host,Proto,Url} 四个 http 头
}

type CustomHeader struct {
	Reset  map[string]string `yaml:"reset"`  // 需要重置的header字段
	Add    map[string]string `yaml:"add"`    // 需要在原有基础上增加的header字段
	Delete []string          `yaml:"delete"` // 需要删掉的header字段
}

type CustomReplace struct {
	Conditions []Condition `yaml:"conditions"` // 查找条件
	FlagReq    bool        `yaml:"-" json:"-"` // conditions中的request匹配是否全部成功
	FlagResp   bool        `yaml:"-" json:"-"` // conditions中的response匹配是否全部成功
	Replaces   []Replace   `yaml:"replaces"`   // 替换规则
}

type Condition struct {
	Item   string `yaml:"item"`   // 空表示匹配所有阶段，否则匹配与burp相同request_header，request_body，response_header，response_body，request_param_name（暂不支持），request_param_value（暂不支持）
	Regexp bool   `yaml:"regexp"` // 是否正则匹配
	Match  string `yaml:"match"`  // 匹配的字符串或正则表达式
}

type Replace struct {
	Item    string `yaml:"item"`    // 空表示匹配所有阶段，否则匹配与burp相同request_header，request_body，response_header，response_body，request_param_name（暂不支持），request_param_value（暂不支持）
	Regexp  bool   `yaml:"regexp"`  // 是否正则匹配
	Match   string `yaml:"match"`   // 匹配的字符串或正则表达式
	Replace string `yaml:"replace"` // 要替换成的字符串
}

type HttpDump struct {
	DumpPath     string      `yaml:"dump_path"`     // http包保存路径，如果为空则不启用保存，如果文件名不合法，则保存文件创建失败，不进行保存
	DumpRequest  bool        `yaml:"dump_request"`  // 是否保存request包，false不保存
	DumpResponse bool        `yaml:"dump_response"` // 是否保存response包，false不保存
	FlagReq      bool        `yaml:"-" json:"-"`    // conditions中的request匹配是否全部成功
	FlagResp     bool        `yaml:"-" json:"-"`    // conditions中的response匹配是否全部成功
	Conditions   []Condition `yaml:"conditions"`    // 满足该条件时，保存数据包，若为空则所有都保存
}

// config.yaml是否为空判断
func (c YamlConfig) IsEmpty() bool {
	return reflect.DeepEqual(c, YamlConfig{})
}

// 初始化config.yaml文件
func (yamDate *YamlConfig) Init(filename string) error {
	v := YamlConfig{
		MitmConfig: MitmConfig{
			CaCert: "myproxy.crt",
			CaKey:  "myproxy.pem",
			BasicAuth: BasicAuth{
				Username: "",
				Password: "",
			},
			AllowIpRange: []string{""},
			Restriction: Restriction{
				HostnameAllowed:    []string{""},
				HostnameDisallowed: []string{""},
				PortAllowed:        []string{""},
				PortDisallowed:     []string{""},
				PathAllowed:        []string{""},
				PathDisallowed:     []string{""},
				QueryKeyAllowed:    []string{""},
				QueryKeyDisallowed: []string{""},
				FragmentAllowed:    []string{""},
				FragmentDisallowed: []string{""},
				PostKeyAllowed:     []string{""},
				PostKeyDisallowed:  []string{""},
			},
			Queue: Queue{
				MaxLength: 3000,
			},
			ProxyHeader: ProxyHeader{
				Via:        "",
				XForwarded: false,
			},
			UpstreamProxy: "",
			CustomHeader: CustomHeader{
				Reset:  map[string]string{"Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate"},
				Add:    map[string]string{},
				Delete: []string{"If-Modified-Since", "If-None-Match"},
			},
			CustomReplaces: []CustomReplace{
				{
					Conditions: []Condition{
						{
							Item:   "",
							Regexp: true,
							Match:  "",
						},
					},
					Replaces: []Replace{
						{
							Item:    "",
							Regexp:  true,
							Match:   "",
							Replace: "",
						},
					},
				},
			},
			HttpDump: HttpDump{
				DumpPath:     "",
				DumpRequest:  true,
				DumpResponse: true,
				Conditions: []Condition{
					{
						Item:   "",
						Regexp: true,
						Match:  "",
					},
				},
			},
		},
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, out, os.ModeAppend|os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

// 写入config.yaml文件
func (yamDate *YamlConfig) Write(filename string) error {
	v := yamDate
	out, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, out, os.ModeAppend|os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

// 读取config.yaml文件
func (yamDate *YamlConfig) Load(filename string, v interface{}) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(data, v)
	if err != nil {
		return err
	}
	return nil
}
