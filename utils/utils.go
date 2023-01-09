package utils

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
)

// s：字符串
// p：模式串
// 返回带通配的字符串匹配结果
func IsMatchString(s string, p string) bool {
	// 参考https://blog.csdn.net/weixin_39678570/article/details/123114159
	var dp [][]bool = make([][]bool, len(s)+1)
	for i := 0; i <= len(s); i++ {
		dp[i] = make([]bool, len(p)+1)
		dp[i][0] = false
	}
	dp[0][0] = true
	for i := 0; i < len(p); i++ {
		if p[i] == '*' {
			dp[0][i+1] = true
		} else {
			break
		}
	}
	for i := 0; i < len(s); i++ {
		for j := 0; j < len(p); j++ {
			ii, jj := i+1, j+1
			if s[i] == p[j] || p[j] == '?' {
				dp[ii][jj] = dp[i][j]
			} else if p[j] == '*' {
				dp[ii][jj] = dp[i][jj] || dp[ii][j]
			} else {
				dp[ii][jj] = false
			}
		}
	}
	return dp[len(s)][len(p)]
}

// s：字符串
// p：正则模式串
// 返回正则匹配结果
func IsMatchRegexp(s string, p string) bool {
	result, _ := regexp.MatchString(p, s)
	return result
}

// s：字符串
// p：正则模式串
// 返回匹配结果
func IsMatchHost(s string, p string) bool {
	hostType, _ := regexp.MatchString("^[0-9./-]+$", p)
	if hostType {
		return matchIp(s, p)
	} else {
		return IsMatchString(s, p)
	}
}

func IsContainString(s string, p string) bool {
	return strings.Contains(s, p)
}

func IsContainRegexp(s string, p string) bool {
	re, _ := regexp.Compile(p)
	result := re.FindAllString(s, -1)
	return len(result) > 0
}

func matchIp(s string, p string) bool {
	if strings.Contains(p, "/") {
		// 参考https://blog.csdn.net/insist100/article/details/90475424
		ipb := ip2binary(s)
		ipr := strings.Split(p, "/")
		masklen, err := strconv.ParseUint(ipr[1], 10, 32)
		if err != nil {
			fmt.Println(err)
			return false
		}
		iprb := ip2binary(ipr[0])
		return strings.EqualFold(ipb[0:masklen], iprb[0:masklen])
	} else if strings.Contains(p, "-") {
		ip := strings.Split(s, ".")
		ipr := strings.Split(p, ".")
		for index, str := range ipr {
			if strings.Contains(str, "-") {
				strr := strings.Split(str, "-")
				is, _ := strconv.ParseUint(strr[0], 10, 0)
				ib, _ := strconv.ParseUint(strr[1], 10, 0)
				ipn, _ := strconv.ParseUint(ip[index], 10, 0)
				if is > ib {
					is, ib = ib, is
				}
				if ipn < is || ipn > ib {
					return false
				}
			} else {
				if ip[index] != str {
					return false
				}
			}
		}
		return true
	} else {
		return strings.EqualFold(s, p)
	}
}

// 将IP地址转化为二进制String
func ip2binary(ip string) string {
	str := strings.Split(ip, ".")
	var ipstr string
	for _, s := range str {
		i, err := strconv.ParseUint(s, 10, 8)
		if err != nil {
			fmt.Println(err)
		}
		ipstr = ipstr + fmt.Sprintf("%08b", i)
	}
	return ipstr
}

// s：字符串
// p：正则模式串
// 返回匹配结果
func IsMatchPort(s string, p string) bool {
	if strings.Contains(p, "-") {
		strr := strings.Split(p, "-")
		ps, _ := strconv.ParseUint(strr[0], 10, 0)
		pb, _ := strconv.ParseUint(strr[1], 10, 0)
		pn, _ := strconv.ParseUint(s, 10, 0)
		if ps > pb {
			ps, pb = pb, ps
		}
		if pn < ps || pn > pb {
			return false
		}
	} else {
		if s != p {
			return false
		}
	}
	return true
}

//GZIPEn gzip加密
func GZIPEn(str string) []byte {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(str)); err != nil {
		panic(err)
	}
	if err := gz.Flush(); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	return b.Bytes()
}

//GZIPDe gzip解密
func GZIPDe(in io.ReadCloser) ([]byte, error) {
	reader, err := gzip.NewReader(in)
	if err != nil {
		var out []byte
		return out, err
	}
	defer reader.Close()
	return ioutil.ReadAll(reader)
}

//BREn gzip加密
func BREn(str string) []byte {
	var b bytes.Buffer
	gz := brotli.NewWriter(&b)
	if _, err := gz.Write([]byte(str)); err != nil {
		panic(err)
	}
	if err := gz.Flush(); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	return b.Bytes()
}

//BRDe gzip解密
func BRDe(in io.ReadCloser) ([]byte, error) {
	reader := brotli.NewReader(in)
	return ioutil.ReadAll(reader)
}

// 获取本机ip列表
func GetAllIps() ([]string, error) {
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
					// fmt.Println(ipnet.IP.String())
					ips = append(ips, ipnet.IP.String())
				}
			}
		}
	}
	return ips, nil
}
