// openvpn-signer project main.go
package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"
)

const (
	VERSION    = "1.0"
	GUIDE_PAGE = `<!DOCTYPE html>
<html lang="cn">
<head>
    <meta charset="UTF-8">
    <title>Openvpn cert generator</title>
</head>
<body>
<h1>OpenVPN证书生成</h1>
<hr>
<form submit="/cert">
<input placeholder="请输入自定义客户端名称" type="text" name="host"/>&nbsp;<button type="submit">生成</button>
</form>
</body>
</html>
`
)

type Config struct {
	CAPassword string
	CAHost     string
	Listen     string
}

var g_Config Config

var ROOTDIR = filepath.Dir(os.Args[0])

type CertHelper struct {
	ca    *x509.Certificate
	cakey *rsa.PrivateKey
}

// this will load ca from disk or generate a new one if disk image is not found
func (this *CertHelper) InitCA() (bool, error) {
	var err error = nil
	capath := path.Join(ROOTDIR, "ca.crt")
	cakeypath := path.Join(ROOTDIR, "ca.key")
	if _, err = os.Stat(capath); os.IsNotExist(err) {
		// generate one
		fmt.Println("Creating new CA, HOST=", g_Config.CAHost, ", Password=", g_Config.CAPassword, "...")
		cert, key, err := this.generateSelfSignedCertKey(g_Config.CAHost, []net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"})
		if err != nil {
			return false, err
		}
		err = ioutil.WriteFile(capath, cert, 0644)
		if err == nil {
			err = ioutil.WriteFile(cakeypath, key, 0644)
		}
		if err != nil { // error saving to disk
			return false, err
		}
		return true, nil
	} else {
		fmt.Printf("Loading CA from disk...")
		caFile, err := ioutil.ReadFile(capath)
		if err != nil {
			return false, err
		}
		caBlock, _ := pem.Decode(caFile)

		this.ca, err = x509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			return false, err
		}
		//解析私钥
		keyFile, err := ioutil.ReadFile(cakeypath)
		if err != nil {
			return false, err
		}
		keyBlock, _ := pem.Decode(keyFile)
		this.cakey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return false, err
		}
		fmt.Println("successfully")
		return true, nil
	}
}

func (this *CertHelper) generateSelfSignedCertKey(host string, alternateIPs []net.IP, alternateDNS []string) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"PMSS"},
			OrganizationalUnit: []string{"PMSS"},
			Province:           []string{"Zhejiang"},
			CommonName:         fmt.Sprintf("%s@%d", host, time.Now().Unix()),
			Locality:           []string{"Zhejiang"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	template.IPAddresses = append(template.IPAddresses, alternateIPs...)
	template.DNSNames = append(template.DNSNames, alternateDNS...)

	derBytes, err := x509.CreateCertificate(cryptorand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// Generate cert
	certBuffer := bytes.Buffer{}
	if err := pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, err
	}

	// Generate key
	keyBuffer := bytes.Buffer{}
	if err := pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return nil, nil, err
	}

	this.ca = &template
	this.cakey = priv
	return certBuffer.Bytes(), keyBuffer.Bytes(), nil
}

func (this *CertHelper) generateClientCert(CN string) ([]byte, error) {
	certpl := &x509.Certificate{
		SerialNumber: big.NewInt(mathrand.Int63()), //证书序列号
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"PMSS"},
			OrganizationalUnit: []string{"PMSS"},
			Province:           []string{"Zhejiang"},
			CommonName:         CN,
			Locality:           []string{"Zhejiang"},
		},
		NotBefore:             time.Now().AddDate(0, 0, -1),                                               //证书有效期开始时间
		NotAfter:              time.Now().AddDate(10, 0, 0),                                               //证书有效期结束时间
		BasicConstraintsValid: true,                                                                       //基本的有效性约束
		IsCA:                  false,                                                                      //是否是根证书
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, //证书用途(客户端认证，数据加密)
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		EmailAddresses:        []string{"test@pmss.com"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	} // create a new client cert template
	priKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	cer, err := x509.CreateCertificate(cryptorand.Reader, certpl, this.ca, &priKey.PublicKey, this.cakey)
	if err != nil {
		return nil, err
	}

	//编码证书文件和私钥文件
	cerPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cer,
	}
	cerByte := pem.EncodeToMemory(cerPem)

	buf := x509.MarshalPKCS1PrivateKey(priKey)
	keyPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: buf,
	}
	keyByte := pem.EncodeToMemory(keyPem)
	cerByte = append(cerByte, keyByte...)
	return cerByte, nil
}

func (this *CertHelper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		w.Header().Add("Content-Type", "text/html")
		w.Write([]byte(GUIDE_PAGE))
		return
	}
	p, e := this.generateClientCert(host)
	if e == nil {
		w.Header().Add("Content-Type", "application/octet-stream")
		w.Header().Add("Content-Disposition", "attachment; filename="+host+".pem")
	}
	w.Write(p)
}

func main() {
	fmt.Println("OpenVPN cert creator for PMSS", VERSION)
	mathrand.Seed(time.Now().AddDate(1, 0, 0).UnixNano())
	var cfg string
	flag.StringVar(&cfg, "c", "config.json", "Configure file")
	flag.Parse()
	if !path.IsAbs(cfg) {
		cfg = path.Join(ROOTDIR, cfg)
	}
	b, err := ioutil.ReadFile(cfg)
	if err == nil {
		err = json.Unmarshal(b, &g_Config)
	}
	if err != nil {
		log.Fatal(err)
	}
	certhlp := &CertHelper{}
	bsucc, err := certhlp.InitCA()
	if !bsucc {
		log.Fatalln(err)
	}
	l, err := net.Listen("tcp", g_Config.Listen)
	http.Handle("/cert", certhlp)
	http.Serve(l, nil)
}
