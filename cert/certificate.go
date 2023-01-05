// Package cert 证书管理
package cert

import (
	"crypto/md5"
	crand "crypto/rand"
	"io/ioutil"
	"math/rand"
	"strconv"
	"strings"

	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

var (
	defaultRootCAPem  []byte
	defaultRootKeyPem []byte
)

var (
	defaultRootCA  *x509.Certificate
	defaultRootKey *rsa.PrivateKey
)

func Init(defaultRootCAPemFile, defaultRootKeyPemFile string) {
	var err error
	defaultRootCAPem, err = ioutil.ReadFile(defaultRootCAPemFile)
	if err != nil {
		panic(fmt.Errorf("加载根证书失败: %s", err))
	}
	block, _ := pem.Decode(defaultRootCAPem)
	defaultRootCA, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(fmt.Errorf("加载根证书失败: %s", err))
	}

	defaultRootKeyPem, err = ioutil.ReadFile(defaultRootKeyPemFile)
	if err != nil {
		panic(fmt.Errorf("加载根证书失败: %s", err))
	}
	block, _ = pem.Decode(defaultRootKeyPem)
	defaultRootKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(fmt.Errorf("加载根证书私钥失败: %s", err))
	}
}

// Certificate 证书管理
type Certificate struct {
	cache Cache
}

type Pair struct {
	Cert            *x509.Certificate
	CertBytes       []byte
	PrivateKey      *rsa.PrivateKey
	PrivateKeyBytes []byte
}

func NewCertificate(cache Cache) *Certificate {
	return &Certificate{
		cache: cache,
	}
}

// RootCA 根证书
func GetDefaultRootCAPem() []byte {
	return defaultRootCAPem
}

func GetDefaultRootKeyPem() []byte {
	return defaultRootKeyPem
}

func GenerateRootTlsConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{
					defaultRootCAPem,
				},
				PrivateKey: defaultRootKey,
			},
		},
	}
}

// GenerateTlsConfig 生成TLS配置
func (c *Certificate) GenerateTlsConfig(host string) (*tls.Config, error) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if c.cache != nil {
		// 先从缓存中查找证书
		if cert := c.cache.Get(host); cert != nil {
			tlsConf := &tls.Config{
				Certificates: []tls.Certificate{*cert},
			}

			return tlsConf, nil
		}
	}
	pair, err := c.GeneratePem(host, 1, defaultRootCA, defaultRootKey)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(pair.CertBytes, pair.PrivateKeyBytes)
	// cert, err := tls.X509KeyPair([]byte(defaultRootCAPem), []byte(defaultRootKeyPem))
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if c.cache != nil {
		// 缓存证书
		c.cache.Set(host, &cert)
	}

	return tlsConf, nil
}

// Generate 生成证书
func (c *Certificate) GeneratePem(host string, expireDays int, rootCA *x509.Certificate, rootKey *rsa.PrivateKey) (*Pair, error) {
	// priv, err := rsa.GenerateKey(crand.Reader, 2048)
	pemBlock, _ := pem.Decode(defaultRootKeyPem)
	priv, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	tmpl := c.template(host, expireDays)
	derBytes, err := x509.CreateCertificate(crand.Reader, tmpl, rootCA, &priv.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	serverCert := pem.EncodeToMemory(certBlock)

	keyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	serverKey := pem.EncodeToMemory(keyBlock)

	p := &Pair{
		Cert:            tmpl,
		CertBytes:       serverCert,
		PrivateKey:      priv,
		PrivateKeyBytes: serverKey,
	}

	return p, nil
}

// GenerateCA 生成根证书
func (c *Certificate) GenerateCA() (*Pair, error) {
	priv, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63()),
		Subject: pkix.Name{
			CommonName:   "MyProxy",
			Country:      []string{"MyProxy"},
			Organization: []string{"MyProxy"},
			Province:     []string{"MyProxy"},
			Locality:     []string{"MyProxy"},
		},
		NotBefore:             time.Now().AddDate(0, -1, 0),
		NotAfter:              time.Now().AddDate(30, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		// MaxPathLen:            2,
		// ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// EmailAddresses:        []string{"admin@admin.com"},
	}

	derBytes, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	serverCert := pem.EncodeToMemory(certBlock)

	keyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	serverKey := pem.EncodeToMemory(keyBlock)

	p := &Pair{
		Cert:            tmpl,
		CertBytes:       serverCert,
		PrivateKey:      priv,
		PrivateKeyBytes: serverKey,
	}

	return p, nil
}

func (c *Certificate) template(host string, expireYears int) *x509.Certificate {
	certDerBlock, _ := pem.Decode(defaultRootCAPem)
	x509RootCACert, _ := x509.ParseCertificate(certDerBlock.Bytes)
	hostMd5 := md5.Sum([]byte(host))
	serialNumber, _ := strconv.ParseInt(hex.EncodeToString(hostMd5[:7]), 16, 64)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: x509RootCACert.NotBefore,
		NotAfter:  x509RootCACert.NotAfter,
		// NotBefore: time.Now().AddDate(-1, 0, 0),
		// NotAfter:  time.Now().AddDate(expireYears, 0, 0),
		// BasicConstraintsValid: true,
		// ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		// EmailAddresses:        []string{"admin@admin.com"},
	}
	hosts := strings.Split(host, ",")
	for _, item := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		} else {
			cert.DNSNames = append(cert.DNSNames, item)
		}
	}

	return cert
}
