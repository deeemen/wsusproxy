package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type (
	MITMProxy struct {
		CA *tls.Certificate
		*zap.Logger
		Dumper
	}
	SSLProxy struct {
		CA *tls.Certificate
		*zap.Logger
		Dumper
	}
)

const (
	certIssuedAgo  = 365 * 24 * time.Hour
	certValidUntil = 365 * 24 * time.Hour
	keyUsage       = x509.KeyUsageCRLSign |
		x509.KeyUsageCertSign |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageDigitalSignature
)

func (p *MITMProxy) loadCA(certPath, keyPath string) error {
	//load TLS CA and key
	cer, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return errors.Wrap(err, "failed to load x509 key pair")
	}
	if len(cer.Certificate) != 1 {
		return errors.New("proxy CA crt file contains > 1 certificate")
	}
	leaf, err := x509.ParseCertificate(cer.Certificate[0])
	if err != nil {
		return errors.Wrap(err, "failed to parse CA leaf cert")
	}
	cer.Leaf = leaf
	p.CA = &cer
	return nil
}

func gencert(ca *tls.Certificate, names ...string) (*tls.Certificate, error) {
	if !ca.Leaf.IsCA {
		return nil, errors.New("non-ca cert used")
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	//serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	serialNumber := new(big.Int).Rand(rnd, serialNumberLimit)
	/*if err != nil {
		return nil, err
	}*/

	templ := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             time.Now().Add(-certIssuedAgo),
		NotAfter:              time.Now().Add(certValidUntil),
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		DNSNames:              names,
		SignatureAlgorithm:    x509.SHA1WithRSA,
		//SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	key, err := rsa.GenerateKey(rnd, 1024)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate rsa key")
	}
	xcert, err := x509.CreateCertificate(rnd, templ, ca.Leaf, key.Public(), ca.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create x509 cert")
	}

	cert := &tls.Certificate{
		Certificate: append([][]byte{}, xcert),
		PrivateKey:  key,
	}
	cert.Leaf, _ = x509.ParseCertificate(xcert)

	return cert, nil
}
func hijackAndHandshake(w http.ResponseWriter, config *tls.Config) (net.Conn, error) {
	raw, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "no upstream", http.StatusServiceUnavailable)
		return nil, err
	}
	if _, err := raw.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		raw.Close()
		return nil, err
	}
	conn := tls.Server(raw, config)
	err = conn.Handshake()
	if err != nil {
		conn.Close()
		raw.Close()
		return nil, err
	}
	return conn, nil
}
func copyConn(cancel context.CancelFunc, from, to net.Conn) {
	defer cancel()
	for {
		readbuf := make([]byte, 1024)
		nread, err := from.Read(readbuf)

		writebuf := readbuf[:nread]
		for len(writebuf) > 0 {
			nwritten, err := to.Write(writebuf)
			if nwritten > 0 {
				writebuf = writebuf[nwritten:]
			}
			if err != nil {
				log.Println("conn write error:", err)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Println("conn read error:", err)
			}
			return
		}
	}
}
func (p SSLProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	remoteConn, err := tls.Dial("tcp", r.Host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		p.Logger.Error(
			"failed to dial remote",
			zap.Error(err),
			zap.String("host", r.Host),
		)
		panic(http.ErrAbortHandler)
	}
	cliConf := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" {
				return gencert(p.CA, hello.ServerName)
			}
			host, _, err := net.SplitHostPort(r.Host)
			if err == nil && host != "" {
				return gencert(p.CA, host)
			}
			return nil, errors.New("no server name to generate mitm cert")
		},
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS11,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	cliConn, err := hijackAndHandshake(w, cliConf)
	if err != nil {
		p.Logger.Error(
			"failed to hijack client connection",
			zap.Error(err),
		)
		panic(http.ErrAbortHandler)
	}
	defer cliConn.Close()

	/*
		go copyConn(cancel, remoteConn, cliConn)
		go copyConn(cancel, cliConn, remoteConn)
		<-ctx.Done()
	*/
	cachedDial := func(net, addr string) (net.Conn, error) {
		if addr == r.Host {
			return remoteConn, nil
		}
		p.Logger.Warn(
			"hijacked connection tried to escape",
			zap.String("connected-with", r.Host),
			zap.String("wants", addr),
		)
		return nil, errors.New("attempt to escape from hijacked conn")
	}

	rproxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Host = r.Host
			r.URL.Scheme = "https"

			p.Logger.Info(
				"request to",
				zap.String("proto", r.Proto),
				zap.String("method", r.Method),
				zap.Stringer("url", r.URL),
			)
		},
		Transport: RoundTripNestedDumper{
			Dumper: p.Dumper,
			RoundTripper: &http.Transport{
				DialTLS: cachedDial,
			},
		},
		ModifyResponse: func(r *http.Response) error {
			/*r.Proto = "HTTP/1.1"
			r.ProtoMajor = 1
			r.ProtoMinor = 1
			*/
			r.Header.Set("Connection", "close")
			return nil
		},
	}
	l := NewOneShotListener(cliConn)
	http.Serve(l, rproxy)
	select {
	case <-ctx.Done():
	case <-l.ConnCloseCh():
	}
}

func (p *MITMProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ts := getTimeStamp()

	log := p.Logger.Named(ts)
	dumper, err := p.Dumper.Inner(ts)
	if err != nil {
		log.Error("failed to create dumper", zap.Error(err))
		panic(http.ErrAbortHandler)

	}
	//save incoming proxy request
	if err := dumper.Request(r, "request"); err != nil {
		log.Error("failed to save request", zap.Error(err))
		panic(http.ErrAbortHandler)
	}

	log.Info(
		"mitm request",
		zap.String("remote", r.RemoteAddr),
		zap.String("proto", r.Proto),
		zap.String("method", r.Method),
		zap.Stringer("url", r.URL),
	)
	switch r.Method {
	case http.MethodConnect:
		SSLProxy{
			CA:     p.CA,
			Logger: log,
			Dumper: dumper,
		}.ServeHTTP(w, r)
	default:
		proxy := &httputil.ReverseProxy{
			Director: func(r *http.Request) {},
			Transport: RoundTripDumper{
				Dumper:       dumper,
				RoundTripper: http.DefaultTransport,
			},
			ModifyResponse: func(r *http.Response) error {
				/*r.Proto = "HTTP/1.1"
				r.ProtoMajor = 1
				r.ProtoMinor = 1
				*/
				return nil
			},
		}
		proxy.ServeHTTP(w, r)
	}
}

func stripRangeFromURL(next http.Handler, log *zap.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			c := strings.Split(r.URL.Path, "@")
			if len(c) == 3 {
				newPath := c[0]
				b1, b2 := int(0), int(0)
				_, err := fmt.Sscanf(c[1], "%d-%d", &b1, &b2)
				if err == nil {
					log.Info(
						"removed range from URL",
						zap.Int("start", b1),
						zap.Int("end", b2),
						zap.String("newpath", newPath),
					)
					r.URL.Path = newPath
					r.Header.Set("Range",
						fmt.Sprintf("bytes=%d-%d", b1, b2))
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

/*
func main() {
	caCert, err := loadCA("server.crt", "server.key")
	if err != nil {
		panic(err)
	}
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doLog(r)
		switch r.Method {
		case http.MethodConnect:
			serveConnect(caCert, w, r)
		default:
			(&httputil.ReverseProxy{
				Director: func(r *http.Request) {
					if strings.Contains(r.URL.Path, "redirect.js") {
						panic(http.ErrAbortHandler)
					}
					if strings.ToLower(r.URL.Host) == "www.update.microsoft.com" {
						r.URL.Host = "fe2.update.microsoft.com"
						r.Host = r.URL.Host
						//r.URL.Path = "/windowsupdate" + r.URL.Path
						log.Println("PATCHED WU URL")
					}
				},
			}).ServeHTTP(w, r)
		}
	})
	err = http.ListenAndServe("0.0.0.0:10080", proxyHandler)
	log.Println(err)
}
*/
