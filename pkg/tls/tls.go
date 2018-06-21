package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"
)

func newPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func newCert(key *rsa.PrivateKey, template *x509.Certificate, signingkey *rsa.PrivateKey, signingcert *x509.Certificate) (*x509.Certificate, error) {
	if signingcert == nil && signingkey == nil {
		// make it self-signed
		signingcert = template
		signingkey = key
	}

	b, err := x509.CreateCertificate(rand.Reader, template, signingcert, key.Public(), signingkey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(b)
}

type serialNumber struct {
	m sync.Mutex
	i int64
}

func (s *serialNumber) Get() *big.Int {
	s.m.Lock()
	defer s.m.Unlock()

	s.i++
	return big.NewInt(s.i)
}

var serial serialNumber

func NewCA(cn string) (*rsa.PrivateKey, *x509.Certificate, error) {
	now := time.Now()

	template := &x509.Certificate{
		SerialNumber:          serial.Get(),
		NotBefore:             now,
		NotAfter:              now.AddDate(5, 0, 0),
		Subject:               pkix.Name{CommonName: cn},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:                  true,
	}

	key, err := newPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	cert, err := newCert(key, template, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

func NewCert(cn string, dnsNames []string, ipAddresses []net.IP, signingkey *rsa.PrivateKey, signingcert *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate, error) {
	now := time.Now()

	template := &x509.Certificate{
		SerialNumber:          serial.Get(),
		NotBefore:             now,
		NotAfter:              now.AddDate(2, 0, 0),
		Subject:               pkix.Name{CommonName: cn},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	key, err := newPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	cert, err := newCert(key, template, signingkey, signingcert)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

func PrivateKeyAsBytes(key *rsa.PrivateKey) ([]byte, error) {
	buf := &bytes.Buffer{}

	err := pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func CertAsBytes(cert *x509.Certificate) ([]byte, error) {
	buf := &bytes.Buffer{}

	err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func ParseBase64PrivateKey(s string) (*rsa.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func MustParseBase64PrivateKey(s string) *rsa.PrivateKey {
	key, err := ParseBase64PrivateKey(s)
	if err != nil {
		panic(err)
	}

	return key
}

func ParseBase64Cert(s string) (*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, err
}

func MustParseBase64Cert(s string) *x509.Certificate {
	cert, err := ParseBase64Cert(s)
	if err != nil {
		panic(err)
	}

	return cert
}

func ParseBase64PublicKey(s string) (*rsa.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key.(*rsa.PublicKey), nil
}

func intsha1(n *big.Int) []byte {
	h := sha1.New()
	h.Write(n.Bytes())
	return h.Sum(nil)
}
